#!/usr/bin/env php
<?php

declare(strict_types=1);

ini_set('memory_limit', '2048M');

require __DIR__ . '/vendor/autoload.php';

use PhpParser\Error;
use PhpParser\Node;
use PhpParser\NodeFinder;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitor\ParentConnectingVisitor;
use PhpParser\NodeVisitorAbstract;
use PhpParser\ParserFactory;
use PhpParser\PhpVersion;
use PhpParser\PrettyPrinter;

/**
 * Uso:
 *   1. Apenas vulnerabilidades com rastro de Input confirmado (usando todos os cores via Swoole):
 *      php ast_collector_nikic.php --path=/caminho/projeto --exclude=vendor --out=saida.json --taint-only
 *
 *   2. Definir número de workers Swoole manualmente (ex: 8 processos paralelos):
 *      php ast_collector_nikic.php --path=/caminho/projeto --taint-only --workers=8 --out=saida.json
 */

$options = getopt('', [
    'path:',
    'exclude::',
    'out::',
    'workers::',
    'taint-only',
    'taint-params',
    'all-calls',
]);

$targetPath = $options['path'] ?? ($argv[1] ?? null);
if (!$targetPath || !file_exists((string)$targetPath)) {
    fwrite(
        STDERR,
        "Uso: php ast_collector_nikic.php --path=/caminho/do/projeto [--exclude=dir1,dir2] [--out=saida.json] [--workers=N] [--taint-only] [--taint-params]\n"
    );
    exit(1);
}

$targetPath      = realpath((string)$targetPath);
$taintOnly       = isset($options['taint-only']);
$taintParams     = isset($options['taint-params']);
$captureAllCalls = isset($options['all-calls']);

$defaultCPU = function_exists('swoole_cpu_num') ? swoole_cpu_num() : 4;
$workers    = isset($options['workers']) ? max(1, (int)$options['workers']) : $defaultCPU;

$defaultExcludes = ['.git', '.svn', '.idea', '.vscode', 'storage/framework', 'var/cache', 'runtime'];
$userExcludes = isset($options['exclude']) && $options['exclude'] !== ''
    ? array_map('trim', explode(',', (string)$options['exclude']))
    : ['vendor', 'node_modules'];

$excludeDirs = array_values(array_unique(array_filter(array_merge($defaultExcludes, $userExcludes))));

// ============================================================================
// MOTOR DE TAINT ANALYSIS + DETECTOR MULTI-FRAMEWORK NA AST
// ============================================================================
class TaintAndSinkVisitor extends NodeVisitorAbstract
{
    /** Funções nativas que representam Sinks perigosos */
    private const FUNC_SINKS = [
        'RCE' => [
            'eval',
            'assert',
            'system',
            'exec',
            'shell_exec',
            'passthru',
            'popen',
            'proc_open',
            'pcntl_exec',
            'preg_replace',
            'create_function',
            'call_user_func',
            'call_user_func_array',
            'forward_static_call',
            'forward_static_call_array',
            'unserialize',
        ],
        'FILE_WRITE' => [
            'file_put_contents',
            'fwrite',
            'fputs',
            'move_uploaded_file',
            'chmod',
            'chown',
            'chgrp',
            'unlink',
            'rmdir',
            'rename',
            'copy',
            'mkdir',
            'tempnam',
            'tmpfile',
            'symlink',
            'link',
        ],
        'SQL_INJECTION' => [
            'mysqli_query',
            'mysqli_multi_query',
            'mysqli_real_query',
            'mysqli_prepare',
            'mysql_query',
            'pg_query',
            'pg_send_query',
            'sqlite_query',
            'sqlite_exec',
            'odbc_exec',
            'oci_parse',
        ],
    ];

    /**
     * Métodos de instância/estáticos de Frameworks que executam SQL cru (SQLi)
     * Cobre: PDO, Laravel/Hyperf (Eloquent/QueryBuilder), Symfony/Doctrine,
     *        Yii2/3, CakePHP, CodeIgniter, Phalcon, Laminas, Nette
     */
    private const SQL_FRAMEWORK_METHODS = [
        // PDO / Genéricos / CodeIgniter / Laminas / Nette / CakePHP
        'query'            => [0],
        'exec'             => [0],
        'rawquery'         => [0],
        ' fetchall'        => [0],
        // Laravel & Hyperf (Query Builder / Eloquent / DB Facade)
        'raw'              => [0],
        'selectraw'        => [0],
        'whereraw'         => [0],
        'orwhereraw'       => [0],
        'havingraw'        => [0],
        'orhavingraw'      => [0],
        'orderbyraw'       => [0],
        'groupbyraw'       => [0],
        'fromraw'          => [0],
        'unprepared'       => [0],
        'statement'        => [0],
        'select'           => [0],
        'affectingstatement' => [0],
        // Symfony / Doctrine DBAL & ORM / Phalcon
        'createquery'      => [0],
        'executequery'     => [0],
        'executestatement' => [0],
        'executeupdate'    => [0],
        // Yii2 / Yii3
        'createcommand'    => [0],
        'findbysql'        => [0],
    ];

    /** Métodos de Frameworks que causam RCE / Command Injection */
    private const RCE_FRAMEWORK_METHODS = [
        'fromshellcommandline' => [0], // Symfony Process
        'command'              => [0], // Swoole / Wrappers
    ];

    /** Métodos de Frameworks que gravam/movem arquivos */
    private const FILE_FRAMEWORK_METHODS = [
        'put'            => [0, 1], // Laravel Storage::put / File::put
        'putfileas'      => [0, 2],
        'move'           => [0, 1], // UploadedFile::move (Symfony / Laravel / CI4 / Phalcon)
        'storeas'        => [0, 1], // Laravel UploadedFile::storeAs
        'moveto'         => [0],    // PSR-7 UploadedFileInterface::moveTo (Slim / Laminas / Hyperf)
        'dumpfile'       => [0, 1], // Symfony Filesystem
    ];

    private const INCLUDE_TYPES = [
        Node\Expr\Include_::TYPE_INCLUDE      => 'include',
        Node\Expr\Include_::TYPE_INCLUDE_ONCE => 'include_once',
        Node\Expr\Include_::TYPE_REQUIRE      => 'require',
        Node\Expr\Include_::TYPE_REQUIRE_ONCE => 'require_once',
    ];

    /** Superglobais que representam entrada direta do usuário */
    private const USER_SUPERGLOBALS = [
        '_GET',
        '_POST',
        '_REQUEST',
        '_COOKIE',
        '_FILES',
        'HTTP_GET_VARS',
        'HTTP_POST_VARS',
        'HTTP_COOKIE_VARS',
        'HTTP_POST_FILES',
    ];

    /** Chaves de $_SERVER controláveis pelo cliente HTTP */
    private const TAINTED_SERVER_KEYS = [
        'QUERY_STRING',
        'REQUEST_URI',
        'PATH_INFO',
        'PHP_SELF',
        'HTTP_USER_AGENT',
        'HTTP_REFERER',
        'HTTP_HOST',
        'HTTP_ACCEPT',
        'HTTP_X_FORWARDED_FOR',
        'HTTP_CLIENT_IP',
        'CONTENT_TYPE',
    ];

    /** Funções que eliminam o risco de injeção no galho avaliado */
    private const STRONG_SANITIZERS = [
        'intval',
        'floatval',
        'doubleval',
        'boolval',
        'count',
        'sizeof',
        'strlen',
        'md5',
        'sha1',
        'hash',
        'hash_hmac',
        'base64_encode',
        'urlencode',
        'rawurlencode',
        'escapeshellarg',
        'ctype_digit',
        'ctype_alnum',
        'is_int',
        'is_numeric',
        'abs',
        'round',
        'floor',
        'ceil',
    ];

    /**
     * Métodos de objetos Request em:
     * Laravel, Symfony, CodeIgniter 3/4, Yii 2/3, CakePHP, Slim, Phalcon, Laminas, Nette, Hyperf
     */
    private const INPUT_METHODS = [
        // Laravel / Hyperf / Symfony
        'input',
        'query',
        'post',
        'get',
        'all',
        'only',
        'except',
        'cookie',
        'header',
        'json',
        'string',
        'str',
        'fluent',
        'collect',
        'payload',
        'getcontent',
        'toarray',
        // PSR-7 (Slim, Laminas, Hyperf, Mezzio)
        'getparsedbody',
        'getqueryparams',
        'getcookieparams',
        'getheaders',
        'getheader',
        'getheaderline',
        'getbody',
        'getuploadedfiles',
        'getattributes',
        'getattribute',
        // CodeIgniter 4 & Phalcon
        'getpost',
        'getget',
        'getvar',
        'getjsonvar',
        'getrawinput',
        'getput',
        'getpatch',
        'getjsonrawbody',
        'getrawbody',
        'getquery',
        // CakePHP
        'getdata',
        'getparam',
        'getparams',
        // Yii 2 / 3
        'getbodyparam',
        'getbodyparams',
        'getqueryparam',
        // Nette
        'getparameter',
        'getparameters',
        'getpost',
        'getrawbody',
    ];

    public array $findings = [];
    private array $funcLookup = [];
    private array $fileLines;
    private bool $taintOnly;
    private bool $taintParams;
    private bool $captureAllCalls;
    private PrettyPrinter\Standard $printer;
    private NodeFinder $nodeFinder;
    private ?string $currentClassName = null;
    private bool $isInsideControllerOrPresenter = false;

    /**
     * Pilha de escopos de Taint
     * @var array<int, array<string, array{source: string, trace: array<int, string>}>>
     */
    private array $taintScopes = [[]];

    public function __construct(string $fileContent, bool $taintOnly, bool $taintParams, bool $captureAllCalls)
    {
        $this->fileLines       = explode("\n", $fileContent);
        $this->taintOnly       = $taintOnly;
        $this->taintParams     = $taintParams;
        $this->captureAllCalls = $captureAllCalls;
        $this->printer         = new PrettyPrinter\Standard();
        $this->nodeFinder      = new NodeFinder();

        foreach (self::FUNC_SINKS as $category => $functions) {
            foreach ($functions as $fn) {
                $this->funcLookup[$fn] = $category;
            }
        }
    }

    public function enterNode(Node $node): void
    {
        // ====================================================================
        // A0. RASTREAMENTO DE CLASSES (Detecta Controllers / Presenters / Actions)
        // ====================================================================
        if ($node instanceof Node\Stmt\Class_) {
            $this->currentClassName = $node->name ? $node->name->toString() : 'AnonymousClass';
            $extendsName = $node->extends ? $node->extends->toString() : '';

            $combined = strtolower($this->currentClassName . ' ' . $extendsName);
            $this->isInsideControllerOrPresenter = str_contains($combined, 'controller')
                || str_contains($combined, 'presenter')
                || str_contains($combined, 'action')
                || str_contains($combined, 'resource');
            return;
        }

        // ====================================================================
        // A. GERENCIAMENTO DE ESCOPO (Funções / Métodos / Closures / ArrowFn)
        // ====================================================================
        if (
            $node instanceof Node\Stmt\Function_
            || $node instanceof Node\Stmt\ClassMethod
            || $node instanceof Node\Expr\Closure
            || $node instanceof Node\Expr\ArrowFunction
        ) {
            // ArrowFunction herda variáveis do escopo pai automaticamente
            $newScope = ($node instanceof Node\Expr\ArrowFunction)
                ? ($this->taintScopes[count($this->taintScopes) - 1] ?? [])
                : [];

            // Se for Closure com `use ($x)`, propaga o taint das variáveis importadas
            if ($node instanceof Node\Expr\Closure) {
                foreach ($node->uses as $use) {
                    if ($use->var instanceof Node\Expr\Variable && is_string($use->var->name)) {
                        $uKey = '$' . $use->var->name;
                        $parentTaint = $this->getTaint($uKey);
                        if ($parentTaint !== null) {
                            $newScope[$uKey] = $parentTaint;
                        }
                    }
                }
            }

            // Auto-taint em parâmetros se:
            // 1. --taint-params estiver ativo, OU
            // 2. For um método público dentro de um Controller/Presenter (parâmetros de rota HTTP!)
            $isPublicControllerAction = ($node instanceof Node\Stmt\ClassMethod)
                && $node->isPublic()
                && $this->isInsideControllerOrPresenter
                && !str_starts_with($node->name->toString(), '__');

            if ($this->taintParams || $isPublicControllerAction) {
                foreach ($node->getParams() as $param) {
                    if ($this->isSafeTypehint($param->type) || $this->isNonInputObjectTypehint($param->type)) {
                        continue;
                    }
                    if ($param->var instanceof Node\Expr\Variable && is_string($param->var->name)) {
                        $pName = '$' . $param->var->name;
                        $line = $param->getStartLine();
                        $origin = $isPublicControllerAction ? "route_param:{$pName}" : "param:{$pName}";
                        $newScope[$pName] = [
                            'source' => $origin,
                            'trace'  => ["Linha {$line}: Parâmetro de entrada recebido ({$origin})"],
                        ];
                    }
                }
            }

            $this->taintScopes[] = $newScope;
            return;
        }

        // Suporte a `global $var;`
        if ($node instanceof Node\Stmt\Global_) {
            foreach ($node->vars as $gVar) {
                if ($gVar instanceof Node\Expr\Variable && is_string($gVar->name)) {
                    $vKey = '$' . $gVar->name;
                    if (isset($this->taintScopes[0][$vKey])) {
                        $this->setTaint($vKey, $this->taintScopes[0][$vKey]['source'], $this->taintScopes[0][$vKey]['trace']);
                    }
                }
            }
            return;
        }

        // Suporte a `extract($_GET)` e `parse_str($str, $out)`
        if ($node instanceof Node\Expr\FuncCall && $node->name instanceof Node\Name) {
            $fn = strtolower($node->name->getLast());
            $args = $node->getArgs();

            if ($fn === 'extract' && !empty($args)) {
                $taintInfo = $this->inspectExpressionTaint($args[0]->value);
                if ($taintInfo !== null) {
                    $line = $node->getStartLine();
                    $trace = $taintInfo['trace'];
                    $trace[] = "Linha {$line}: extract() importou variáveis de {$taintInfo['source']} para o escopo";
                    $this->setTaint('$__EXTRACT_TAINTED__', $taintInfo['source'], $trace);
                }
            } elseif (($fn === 'parse_str' || $fn === 'mb_parse_str') && !empty($args)) {
                $taintInfo = $this->inspectExpressionTaint($args[0]->value);
                if ($taintInfo !== null) {
                    $line = $node->getStartLine();
                    $trace = $taintInfo['trace'];
                    if (isset($args[1])) {
                        $targetKey = $this->resolveVariableKey($args[1]->value);
                        if ($targetKey !== null) {
                            $trace[] = "Linha {$line}: {$fn}() populou {$targetKey} a partir de {$taintInfo['source']}";
                            $this->setTaint($targetKey, $taintInfo['source'], $trace);
                        }
                    } else {
                        $trace[] = "Linha {$line}: {$fn}() sem 2º argumento sujou o escopo local";
                        $this->setTaint('$__EXTRACT_TAINTED__', $taintInfo['source'], $trace);
                    }
                }
            }
        }

        // ====================================================================
        // B. PROPAGAÇÃO DE TAINT EM ATRIBUIÇÕES ($a = ...; [$a, $b] = ...;)
        // ====================================================================
        if ($node instanceof Node\Expr\Assign || $node instanceof Node\Expr\AssignOp) {
            // Suporte a destruturação: [$a, $b] = $_POST['dados'] ou list($a, $b) = ...
            if ($node instanceof Node\Expr\Assign && ($node->var instanceof Node\Expr\Array_ || $node->var instanceof Node\Expr\List_)) {
                $rhsTaint = $this->inspectExpressionTaint($node->expr);
                if ($rhsTaint !== null) {
                    $line = $node->getStartLine();
                    foreach ($node->var->items as $item) {
                        if ($item !== null) {
                            $tKey = $this->resolveVariableKey($item->value);
                            if ($tKey !== null) {
                                $trace = $rhsTaint['trace'];
                                $trace[] = "Linha {$line}: {$tKey} contaminado via destruturação de array";
                                $this->setTaint($tKey, $rhsTaint['source'], $trace);
                            }
                        }
                    }
                }
            } else {
                $targetKey = $this->resolveVariableKey($node->var);
                if ($targetKey !== null) {
                    if ($this->isSanitizedExpression($node->expr)) {
                        if ($node instanceof Node\Expr\Assign) {
                            $this->clearTaint($targetKey);
                        }
                    } else {
                        $rhsTaint = $this->inspectExpressionTaint($node->expr);
                        if ($rhsTaint !== null) {
                            $line = $node->getStartLine();
                            $exprCode = $this->shortenCode($this->printer->prettyPrintExpr($node));
                            $newTrace = $rhsTaint['trace'];
                            $newTrace[] = "Linha {$line}: {$targetKey} contaminado via `{$exprCode}`";
                            $this->setTaint($targetKey, $rhsTaint['source'], $newTrace);
                        } elseif ($node instanceof Node\Expr\Assign) {
                            $this->clearTaint($targetKey);
                        }
                    }
                }
            }
        }

        // Propagação em foreach ($taintedArray as $k => $v)
        if ($node instanceof Node\Stmt\Foreach_) {
            $exprTaint = $this->inspectExpressionTaint($node->expr);
            if ($exprTaint !== null) {
                $line = $node->getStartLine();
                foreach ([$node->keyVar, $node->valueVar] as $loopVar) {
                    if ($loopVar !== null) {
                        $valKey = $this->resolveVariableKey($loopVar);
                        if ($valKey !== null) {
                            $newTrace = $exprTaint['trace'];
                            $newTrace[] = "Linha {$line}: {$valKey} iterado via `foreach ({$this->printer->prettyPrintExpr($node->expr)})`";
                            $this->setTaint($valKey, $exprTaint['source'], $newTrace);
                        }
                    }
                }
            }
        }

        // ====================================================================
        // C. VERIFICAÇÃO DE SINKS (RCE, FILE_WRITE, SQL_INJECTION)
        // ====================================================================

        // 1. eval()
        if ($node instanceof Node\Expr\Eval_) {
            $this->evaluateAndRecordSink($node, 'RCE', 'eval', [$node->expr]);
            return;
        }

        // 2. Backticks: `$cmd` (Equivalente a shell_exec)
        if ($node instanceof Node\Expr\ShellExec) {
            $this->evaluateAndRecordSink($node, 'RCE', 'backticks_shell_exec', $node->parts);
            return;
        }

        // 3. include / require
        if ($node instanceof Node\Expr\Include_) {
            $sinkName = self::INCLUDE_TYPES[$node->type] ?? 'include';
            $this->evaluateAndRecordSink($node, 'RCE', $sinkName, [$node->expr]);
            return;
        }

        // 4. Chamadas de funções globais
        if ($node instanceof Node\Expr\FuncCall && $node->name instanceof Node\Name) {
            $funcName = strtolower($node->name->getLast());
            if (!isset($this->funcLookup[$funcName])) {
                return;
            }

            $category = $this->funcLookup[$funcName];
            $args = $node->getArgs();

            if ($funcName === 'preg_replace') {
                $relevantExprs = $this->getPregReplaceRelevantExprs($args);
                if (!empty($relevantExprs)) {
                    $this->evaluateAndRecordSink($node, $category, $funcName, $relevantExprs);
                }
                return;
            }

            if (in_array($funcName, ['call_user_func', 'call_user_func_array', 'forward_static_call', 'forward_static_call_array'], true)) {
                $callbackExpr = isset($args[0]) ? [$args[0]->value] : [];
                $this->evaluateAndRecordSink($node, $category, $funcName, $callbackExpr);
                return;
            }

            $argExprs = array_map(static fn(Node\Arg $a) => $a->value, $args);
            $this->evaluateAndRecordSink($node, $category, $funcName, $argExprs);
            return;
        }

        // 5. Chamadas de Métodos ou Estáticas (Frameworks: Laravel, Symfony, Yii, Cake, CI, Phalcon, Hyperf, etc.)
        if ($node instanceof Node\Expr\MethodCall || $node instanceof Node\Expr\StaticCall) {
            if (!$node->name instanceof Node\Identifier) {
                return;
            }

            $methodName = strtolower($node->name->toString());
            $args = $node->getArgs();
            if (empty($args)) {
                return;
            }

            // 5.1 Sinks de SQL Injection em Frameworks/ORMs
            if (isset(self::SQL_FRAMEWORK_METHODS[$methodName])) {
                $sinkLabel = $this->resolveFrameworkSinkLabel($node, $methodName, 'SQL');
                if ($sinkLabel !== null) {
                    $relevantArgs = $this->extractArgIndexes($args, self::SQL_FRAMEWORK_METHODS[$methodName]);
                    $this->evaluateAndRecordSink($node, 'SQL_INJECTION', $sinkLabel, $relevantArgs);
                    return;
                }
            }

            // 5.2 Sinks de RCE em Frameworks (Symfony Process, Swoole Exec, etc.)
            if (isset(self::RCE_FRAMEWORK_METHODS[$methodName])) {
                $sinkLabel = $this->resolveFrameworkSinkLabel($node, $methodName, 'RCE');
                if ($sinkLabel !== null) {
                    $relevantArgs = $this->extractArgIndexes($args, self::RCE_FRAMEWORK_METHODS[$methodName]);
                    $this->evaluateAndRecordSink($node, 'RCE', $sinkLabel, $relevantArgs);
                    return;
                }
            }

            // 5.3 Sinks de Escrita/Upload de Arquivos em Frameworks
            if (isset(self::FILE_FRAMEWORK_METHODS[$methodName])) {
                $sinkLabel = $this->resolveFrameworkSinkLabel($node, $methodName, 'FILE');
                if ($sinkLabel !== null) {
                    $relevantArgs = $this->extractArgIndexes($args, self::FILE_FRAMEWORK_METHODS[$methodName]);
                    $this->evaluateAndRecordSink($node, 'FILE_WRITE', $sinkLabel, $relevantArgs);
                }
            }
        }
    }

    public function leaveNode(Node $node): void
    {
        if ($node instanceof Node\Stmt\Class_) {
            $this->currentClassName = null;
            $this->isInsideControllerOrPresenter = false;
            return;
        }

        if (
            $node instanceof Node\Stmt\Function_
            || $node instanceof Node\Stmt\ClassMethod
            || $node instanceof Node\Expr\Closure
            || $node instanceof Node\Expr\ArrowFunction
        ) {
            array_pop($this->taintScopes);
        }
    }

    /**
     * @param array<int, Node\Arg> $args
     * @param array<int, int> $indexes
     * @return array<int, Node\Expr>
     */
    private function extractArgIndexes(array $args, array $indexes): array
    {
        $selected = [];
        foreach ($indexes as $idx) {
            if (isset($args[$idx])) {
                $selected[] = $args[$idx]->value;
            }
        }
        return $selected;
    }

    private function evaluateAndRecordSink(Node $sinkNode, string $category, string $sinkName, array $argExprs): void
    {
        $taintHit = null;
        $hasDynamic = false;

        foreach ($argExprs as $expr) {
            if ($this->isExpressionDynamic($expr)) {
                $hasDynamic = true;
            }
            $foundTaint = $this->inspectExpressionTaint($expr);
            if ($foundTaint !== null) {
                $taintHit = $foundTaint;
                break;
            }
        }

        if ($this->taintOnly && $taintHit === null) {
            return;
        }

        if (!$this->captureAllCalls && !$hasDynamic && $taintHit === null) {
            return;
        }

        $line = $sinkNode->getStartLine();
        $scopeNode = $this->findEnclosingScope($sinkNode);

        if ($scopeNode !== null) {
            $scopeLabel = $this->getScopeLabel($scopeNode);
            $startLine  = $scopeNode->getStartLine();
            $endLine    = $scopeNode->getEndLine();

            if (($endLine - $startLine) > 90) {
                $startLine = max($scopeNode->getStartLine(), $line - 35);
                $endLine   = min($scopeNode->getEndLine(), $sinkNode->getEndLine() + 10);
            }
        } else {
            $scopeLabel = 'global_scope';
            $startLine  = max(1, $line - 25);
            $endLine    = min(count($this->fileLines), $sinkNode->getEndLine() + 8);
        }

        $traceSteps = $taintHit['trace'] ?? [];
        if ($taintHit !== null) {
            $traceSteps[] = "Linha {$line}: Chegou ao Sink `{$this->shortenCode($this->printer->prettyPrintExpr($sinkNode))}`";
        }

        $this->findings[] = [
            'category'        => $category,
            'sink'            => $sinkName,
            'line'            => $line,
            'is_tainted'      => $taintHit !== null,
            'taint_source'    => $taintHit['source'] ?? null,
            'taint_trace'     => $traceSteps,
            'enclosing_scope' => $scopeLabel,
            'ast_expression'  => $this->printer->prettyPrintExpr($sinkNode),
            'code_line'       => trim($this->fileLines[$line - 1] ?? ''),
            'scope_range'     => ['start' => $startLine, 'end' => $endLine],
            'context_code'    => $this->extractLines($startLine, $endLine),
        ];
    }

    /**
     * Inspeciona recursivamente uma expressão podando galhos que possuem sanitizadores/casts.
     * Evita o falso positivo de marcar `"SELECT " . intval($_GET['id'])` como vulnerável.
     */
    private function inspectExpressionTaint(Node $expr): ?array
    {
        // Se este nó específico é um sanitizador ou cast seguro, poda a árvore aqui!
        if ($this->isSanitizedExpression($expr)) {
            return null;
        }

        // 1. Verifica se o próprio nó atual é uma fonte direta de input
        $direct = $this->checkSingleNodeDirectSource($expr);
        if ($direct !== null) {
            return $direct;
        }

        // 2. Verifica se o nó atual é uma variável/propriedade já marcada como Tainted
        if (
            $expr instanceof Node\Expr\Variable
            || $expr instanceof Node\Expr\PropertyFetch
            || $expr instanceof Node\Expr\ArrayDimFetch
        ) {
            $key = $this->resolveVariableKey($expr);
            if ($key !== null) {
                $existing = $this->getTaint($key);
                if ($existing !== null) {
                    return $existing;
                }
                $extractTaint = $this->getTaint('$__EXTRACT_TAINTED__');
                if ($extractTaint !== null && $expr instanceof Node\Expr\Variable) {
                    return $extractTaint;
                }
            }
        }

        // 3. Desce recursivamente pelos sub-nós da expressão (respeitando a poda de sanitizadores)
        foreach ($expr->getSubNodeNames() as $name) {
            $subNode = $expr->$name;
            if ($subNode instanceof Node) {
                // Em chamadas de função/método, não inspeciona o nome da função, apenas os argumentos e o objeto
                if (($expr instanceof Node\Expr\FuncCall || $expr instanceof Node\Expr\MethodCall || $expr instanceof Node\Expr\StaticCall) && $name === 'name') {
                    continue;
                }
                $subTaint = $this->inspectExpressionTaint($subNode);
                if ($subTaint !== null) {
                    return $subTaint;
                }
            } elseif (is_array($subNode)) {
                foreach ($subNode as $item) {
                    if ($item instanceof Node) {
                        $subTaint = $this->inspectExpressionTaint($item);
                        if ($subTaint !== null) {
                            return $subTaint;
                        }
                    }
                }
            }
        }

        return null;
    }

    /**
     * Avalia se UM nó específico da AST é uma fonte de entrada (Superglobal ou Request de Framework)
     */
    private function checkSingleNodeDirectSource(Node $n): ?array
    {
        // Caso 1: $_GET['id'], $_POST['cmd'], $_SERVER['HTTP_...']
        if ($n instanceof Node\Expr\ArrayDimFetch) {
            $rootVar = $n->var;
            if ($rootVar instanceof Node\Expr\Variable && is_string($rootVar->name)) {
                $varName = $rootVar->name;

                if (in_array($varName, self::USER_SUPERGLOBALS, true)) {
                    $code = $this->printer->prettyPrintExpr($n);
                    $line = $n->getStartLine();
                    return [
                        'source' => $code,
                        'trace'  => ["Linha {$line}: Input direto capturado de `{$code}`"],
                    ];
                }

                if ($varName === '_SERVER' && $n->dim instanceof Node\Scalar\String_) {
                    $srvKey = strtoupper($n->dim->value);
                    if (str_starts_with($srvKey, 'HTTP_') || in_array($srvKey, self::TAINTED_SERVER_KEYS, true)) {
                        $code = $this->printer->prettyPrintExpr($n);
                        $line = $n->getStartLine();
                        return [
                            'source' => $code,
                            'trace'  => ["Linha {$line}: Cabeçalho/URI HTTP capturado de `{$code}`"],
                        ];
                    }
                }
            }
        }

        // Caso 2: Superglobal acessada inteira ($_GET, $_POST)
        if ($n instanceof Node\Expr\Variable && is_string($n->name)) {
            if (in_array($n->name, self::USER_SUPERGLOBALS, true)) {
                $code = '$' . $n->name;
                $line = $n->getStartLine();
                return [
                    'source' => $code,
                    'trace'  => ["Linha {$line}: Superglobal `{$code}` acessada diretamente"],
                ];
            }
        }

        // Caso 3: Funções globais de input: getenv(), request('x') do Laravel, file_get_contents('php://input')
        if ($n instanceof Node\Expr\FuncCall && $n->name instanceof Node\Name) {
            $fn = strtolower($n->name->getLast());
            if (in_array($fn, ['getenv', 'getallheaders', 'apache_request_headers'], true)) {
                $code = $this->printer->prettyPrintExpr($n);
                $line = $n->getStartLine();
                return [
                    'source' => $code,
                    'trace'  => ["Linha {$line}: Entrada externa lida via `{$code}`"],
                ];
            }
            // Helper `request('campo')` do Laravel / Hyperf
            if ($fn === 'request' && !empty($n->getArgs())) {
                $code = $this->printer->prettyPrintExpr($n);
                $line = $n->getStartLine();
                return [
                    'source' => $code,
                    'trace'  => ["Linha {$line}: Helper `{$code}` (Laravel/Hyperf Request) capturado"],
                ];
            }
            if ($fn === 'file_get_contents' && !empty($n->getArgs())) {
                $firstArg = $n->getArgs()[0]->value;
                if ($firstArg instanceof Node\Scalar\String_ && stripos($firstArg->value, 'php://input') !== false) {
                    $code = $this->printer->prettyPrintExpr($n);
                    $line = $n->getStartLine();
                    return [
                        'source' => 'php://input',
                        'trace'  => ["Linha {$line}: Corpo da requisição HTTP lido via `{$code}`"],
                    ];
                }
            }
        }

        // Caso 4: Chamadas de método em objetos Request dos 10 frameworks
        if ($n instanceof Node\Expr\MethodCall && $n->name instanceof Node\Identifier) {
            $mName = strtolower($n->name->toString());
            if (in_array($mName, self::INPUT_METHODS, true)) {
                $callerStr = strtolower($this->printer->prettyPrintExpr($n->var));
                if (
                    str_contains($callerStr, 'request')
                    || str_contains($callerStr, 'input')
                    || str_contains($callerStr, 'req')
                    || ($this->isInsideControllerOrPresenter && $callerStr === '$this' && in_array($mName, ['getparameter', 'getparameters', 'getparam'], true))
                ) {
                    $code = $this->printer->prettyPrintExpr($n);
                    $line = $n->getStartLine();
                    return [
                        'source' => $code,
                        'trace'  => ["Linha {$line}: Input de Framework capturado via `{$code}`"],
                    ];
                }
            }
        }

        // Caso 5: Facade estática `Request::input('x')`, `Request::get('x')`, `Request::all()` (Laravel)
        if ($n instanceof Node\Expr\StaticCall && $n->class instanceof Node\Name && $n->name instanceof Node\Identifier) {
            $className = strtolower($n->class->getLast());
            $mName = strtolower($n->name->toString());
            if ($className === 'request' && in_array($mName, self::INPUT_METHODS, true)) {
                $code = $this->printer->prettyPrintExpr($n);
                $line = $n->getStartLine();
                return [
                    'source' => $code,
                    'trace'  => ["Linha {$line}: Facade Request capturada via `{$code}`"],
                ];
            }
        }

        // Caso 6: Propriedade mágica no Laravel `$request->campo` (exceto sub-objetos internos do Symfony)
        if ($n instanceof Node\Expr\PropertyFetch && $n->var instanceof Node\Expr\Variable && $n->name instanceof Node\Identifier) {
            $varName = strtolower((string)$n->var->name);
            $propName = strtolower($n->name->toString());
            $symfonySubBags = ['query', 'request', 'attributes', 'cookies', 'files', 'server', 'headers'];

            if (($varName === 'request' || $varName === 'req') && !in_array($propName, $symfonySubBags, true)) {
                $code = $this->printer->prettyPrintExpr($n);
                $line = $n->getStartLine();
                return [
                    'source' => $code,
                    'trace'  => ["Linha {$line}: Propriedade mágica de Request acessada via `{$code}`"],
                ];
            }
        }

        return null;
    }

    private function isSanitizedExpression(Node $expr): bool
    {
        if (
            $expr instanceof Node\Expr\Cast\Int_
            || $expr instanceof Node\Expr\Cast\Double
            || $expr instanceof Node\Expr\Cast\Bool_
        ) {
            return true;
        }

        if (
            $expr instanceof Node\Expr\BinaryOp\Plus
            || $expr instanceof Node\Expr\BinaryOp\Minus
            || $expr instanceof Node\Expr\BinaryOp\Mul
            || $expr instanceof Node\Expr\BinaryOp\Div
        ) {
            return true;
        }

        if ($expr instanceof Node\Expr\FuncCall && $expr->name instanceof Node\Name) {
            $fn = strtolower($expr->name->getLast());
            if (in_array($fn, self::STRONG_SANITIZERS, true)) {
                return true;
            }
        }

        // Métodos de Request do Laravel que já fazem cast para inteiro/booleano/float
        if ($expr instanceof Node\Expr\MethodCall && $expr->name instanceof Node\Identifier) {
            $mName = strtolower($expr->name->toString());
            if (in_array($mName, ['integer', 'boolean', 'float'], true)) {
                return true;
            }
        }

        return false;
    }

    private function isSafeTypehint(?Node $typeNode): bool
    {
        if ($typeNode instanceof Node\Identifier) {
            return in_array(strtolower($typeNode->toString()), ['int', 'float', 'bool'], true);
        }
        return false;
    }

    /**
     * Evita marcar a própria injeção de dependência (ex: `Request $request`, `UserService $service`)
     * como uma string contaminada direta em Controllers.
     */
    private function isNonInputObjectTypehint(?Node $typeNode): bool
    {
        if ($typeNode instanceof Node\Name) {
            return true;
        }
        return false;
    }

    private function resolveVariableKey(Node $node): ?string
    {
        if ($node instanceof Node\Expr\Variable && is_string($node->name)) {
            return '$' . $node->name;
        }
        if (
            $node instanceof Node\Expr\PropertyFetch
            && $node->var instanceof Node\Expr\Variable
            && is_string($node->var->name)
            && $node->name instanceof Node\Identifier
        ) {
            return '$' . $node->var->name . '->' . $node->name->toString();
        }
        if ($node instanceof Node\Expr\ArrayDimFetch && $node->var instanceof Node\Expr\Variable && is_string($node->var->name)) {
            if (in_array($node->var->name, self::USER_SUPERGLOBALS, true)) {
                return null;
            }
            return '$' . $node->var->name;
        }
        return null;
    }

    private function setTaint(string $key, string $source, array $trace): void
    {
        $currentIdx = count($this->taintScopes) - 1;
        $this->taintScopes[$currentIdx][$key] = [
            'source' => $source,
            'trace'  => $trace,
        ];
        if (str_starts_with($key, '$this->')) {
            $this->taintScopes[0][$key] = [
                'source' => $source,
                'trace'  => $trace,
            ];
        }
    }

    private function getTaint(string $key): ?array
    {
        $currentIdx = count($this->taintScopes) - 1;
        if (isset($this->taintScopes[$currentIdx][$key])) {
            return $this->taintScopes[$currentIdx][$key];
        }
        if (str_starts_with($key, '$this->') && isset($this->taintScopes[0][$key])) {
            return $this->taintScopes[0][$key];
        }
        return null;
    }

    private function clearTaint(string $key): void
    {
        $currentIdx = count($this->taintScopes) - 1;
        unset($this->taintScopes[$currentIdx][$key]);
    }

    private function getPregReplaceRelevantExprs(array $args): array
    {
        if (empty($args)) {
            return [];
        }
        $patternExpr = $args[0]->value;

        if ($patternExpr instanceof Node\Scalar\String_) {
            if (preg_match('/[\/#~@%;!][imsxeADSUXJu]*e[imsxeADSUXJu]*$/', $patternExpr->value)) {
                $exprs = [];
                if (isset($args[1])) {
                    $exprs[] = $args[1]->value;
                }
                if (isset($args[2])) {
                    $exprs[] = $args[2]->value;
                }
                return $exprs;
            }
            return [];
        }

        if ($this->isExpressionDynamic($patternExpr)) {
            return [$patternExpr];
        }

        return [];
    }

    private function resolveFrameworkSinkLabel(Node\Expr $callNode, string $methodName, string $type): ?string
    {
        // Ignora `$request->query('id')` para não confundir com `$pdo->query('SELECT...')`
        if ($methodName === 'query' && $callNode instanceof Node\Expr\MethodCall) {
            $callerLower = strtolower($this->printer->prettyPrintExpr($callNode->var));
            if (str_contains($callerLower, 'request') || str_contains($callerLower, 'req') || str_contains($callerLower, 'input')) {
                return null;
            }
        }

        if ($callNode instanceof Node\Expr\StaticCall) {
            if ($callNode->class instanceof Node\Name) {
                $className = $callNode->class->toString();
                $classLower = strtolower($className);

                if ($type === 'SQL') {
                    // DB::select, DB::raw, PDO::query, User::whereRaw, Model::findBySql
                    $sqlStaticMethods = ['whereraw', 'orwhereraw', 'selectraw', 'orderbyraw', 'havingraw', 'groupbyraw', 'fromraw', 'findbysql', 'raw', 'unprepared', 'statement'];
                    if (
                        str_contains($classLower, 'db')
                        || str_contains($classLower, 'pdo')
                        || in_array($methodName, $sqlStaticMethods, true)
                    ) {
                        return $className . '::' . $methodName;
                    }
                    return null;
                }

                if ($type === 'RCE') {
                    if (str_contains($classLower, 'process') || str_contains($classLower, 'coroutine') || str_contains($classLower, 'system')) {
                        return $className . '::' . $methodName;
                    }
                    return null;
                }

                if ($type === 'FILE') {
                    if (str_contains($classLower, 'storage') || str_contains($classLower, 'file')) {
                        return $className . '::' . $methodName;
                    }
                    return null;
                }
            }
            return null;
        }

        if ($callNode instanceof Node\Expr\MethodCall) {
            $callerCode = $this->shortenCode($this->printer->prettyPrintExpr($callNode->var));
            $callerLower = strtolower($callerCode);

            if ($type === 'FILE') {
                if (
                    str_contains($callerLower, 'file')
                    || str_contains($callerLower, 'storage')
                    || str_contains($callerLower, 'upload')
                    || str_contains($callerLower, 'filesystem')
                    || in_array($methodName, ['storeas', 'moveto', 'putfileas'], true)
                ) {
                    return $callerCode . '->' . $methodName;
                }
                return null;
            }

            // Para métodos genéricos de SQL como `select`, exige indício de objeto de banco
            if ($type === 'SQL' && $methodName === 'select') {
                if (!str_contains($callerLower, 'db') && !str_contains($callerLower, 'connection') && !str_contains($callerLower, 'conn')) {
                    return null;
                }
            }

            return $callerCode . '->' . $methodName;
        }

        return null;
    }

    private function isExpressionDynamic(Node $expr): bool
    {
        $dynamicNode = $this->nodeFinder->findFirst($expr, static function (Node $n): bool {
            return $n instanceof Node\Expr\Variable
                || $n instanceof Node\Expr\ArrayDimFetch
                || $n instanceof Node\Expr\PropertyFetch
                || $n instanceof Node\Expr\StaticPropertyFetch
                || $n instanceof Node\Expr\FuncCall
                || $n instanceof Node\Expr\MethodCall
                || $n instanceof Node\Expr\StaticCall
                || $n instanceof Node\Scalar\InterpolatedString
                || $n instanceof Node\Scalar\Encapsed;
        });

        return $dynamicNode !== null;
    }

    private function findEnclosingScope(Node $node): ?Node
    {
        $curr = $node->getAttribute('parent');
        while ($curr !== null) {
            if (
                $curr instanceof Node\Stmt\ClassMethod
                || $curr instanceof Node\Stmt\Function_
                || $curr instanceof Node\Expr\Closure
                || $curr instanceof Node\Expr\ArrowFunction
            ) {
                return $curr;
            }
            $curr = $curr->getAttribute('parent');
        }
        return null;
    }

    private function getScopeLabel(Node $scope): string
    {
        if ($scope instanceof Node\Stmt\ClassMethod) {
            $parent = $scope->getAttribute('parent');
            $className = ($parent instanceof Node\Stmt\Class_ && $parent->name !== null)
                ? $parent->name->toString()
                : ($this->currentClassName ?? 'AnonymousClass');
            return $className . '::' . $scope->name->toString() . '()';
        }
        if ($scope instanceof Node\Stmt\Function_) {
            return $scope->name->toString() . '()';
        }
        return 'closure_line_' . $scope->getStartLine();
    }

    private function shortenCode(string $code): string
    {
        $singleLine = preg_replace('/\s+/', ' ', trim($code)) ?? $code;
        return strlen($singleLine) > 100 ? substr($singleLine, 0, 97) . '...' : $singleLine;
    }

    private function extractLines(int $start, int $end): array
    {
        $slice = [];
        for ($i = $start; $i <= $end; $i++) {
            if (isset($this->fileLines[$i - 1])) {
                $slice[(string)$i] = rtrim($this->fileLines[$i - 1], "\r");
            }
        }
        return $slice;
    }
}

// ============================================================================
// VARREDURA DE DIRETÓRIOS
// ============================================================================
function collectPhpFiles(string $basePath, array $excludeDirs): array
{
    if (is_file($basePath)) {
        return [$basePath];
    }

    $files = [];
    $dirIterator = new RecursiveDirectoryIterator($basePath, RecursiveDirectoryIterator::SKIP_DOTS);
    $filterIterator = new RecursiveCallbackFilterIterator(
        $dirIterator,
        function (SplFileInfo $current) use ($basePath, $excludeDirs): bool {
            $relPath = ltrim(substr($current->getPathname(), strlen($basePath)), DIRECTORY_SEPARATOR);
            $relPathNorm = str_replace('\\', '/', $relPath);

            if ($current->isDir()) {
                $dirName = $current->getFilename();
                foreach ($excludeDirs as $ex) {
                    $exNorm = trim(str_replace('\\', '/', $ex), '/');
                    if ($dirName === $exNorm || $relPathNorm === $exNorm || str_starts_with($relPathNorm, $exNorm . '/')) {
                        return false;
                    }
                }
                return true;
            }

            return in_array(strtolower($current->getExtension()), ['php', 'inc', 'phtml', 'php5', 'php7', 'module'], true);
        }
    );

    foreach (new RecursiveIteratorIterator($filterIterator) as $fileInfo) {
        $files[] = $fileInfo->getPathname();
    }

    sort($files);
    return $files;
}

// ============================================================================
// FUNÇÃO DE PROCESSAMENTO DE UM LOTE DE ARQUIVOS (WORKER OU SEQUENCIAL)
// ============================================================================
function analyzeFileBatch(
    array $fileBatch,
    string $targetPath,
    bool $taintOnly,
    bool $taintParams,
    bool $captureAllCalls
): array {
    $factory = new ParserFactory();
    $parserPhp8 = method_exists($factory, 'createForNewestSupportedVersion')
        ? $factory->createForNewestSupportedVersion()
        : $factory->create(ParserFactory::PREFER_PHP7);

    $parserPhp7 = method_exists($factory, 'createForVersion')
        ? $factory->createForVersion(PhpVersion::fromComponents(7, 4))
        : $parserPhp8;

    $filesWithFindings = [];
    $parseErrors = [];

    foreach ($fileBatch as $filePath) {
        $code = @file_get_contents($filePath);
        if ($code === false || trim($code) === '') {
            continue;
        }

        $normalizedCode = preg_replace('/^<\?(?!php|xml|=)/i', '<?php ', $code) ?? $code;

        $ast = null;
        try {
            $ast = $parserPhp8->parse($normalizedCode);
        } catch (Error $e8) {
            try {
                $ast = $parserPhp7->parse($normalizedCode);
            } catch (Error $e7) {
                $parseErrors[] = [
                    'file'  => $filePath,
                    'error' => $e8->getMessage(),
                ];
                continue;
            }
        }

        if ($ast === null) {
            continue;
        }

        $traverser = new NodeTraverser();
        $traverser->addVisitor(new ParentConnectingVisitor());

        $visitor = new TaintAndSinkVisitor($code, $taintOnly, $taintParams, $captureAllCalls);
        $traverser->addVisitor($visitor);
        $traverser->traverse($ast);

        if (!empty($visitor->findings)) {
            $relativePath = is_dir($targetPath)
                ? ltrim(substr($filePath, strlen($targetPath)), DIRECTORY_SEPARATOR)
                : basename($filePath);

            $filesWithFindings[] = [
                'file'          => str_replace('\\', '/', $relativePath),
                'absolute_path' => $filePath,
                'total_matches' => count($visitor->findings),
                'matches'       => $visitor->findings,
            ];
        }
    }

    return [
        'files'        => $filesWithFindings,
        'parse_errors' => $parseErrors,
    ];
}

// ============================================================================
// EXECUÇÃO PRINCIPAL (PARALELISMO MULTI-PROCESSO COM SWOOLE)
// ============================================================================
$startTime = microtime(true);
$allPhpFiles = collectPhpFiles($targetPath, $excludeDirs);
$totalFiles = count($allPhpFiles);

$canUseSwoole = extension_loaded('swoole')
    && class_exists(\Swoole\Process::class)
    && $workers > 1
    && $totalFiles > 1;

fwrite(STDERR, "[*] Caminho escaneado: {$targetPath}\n");
fwrite(STDERR, "[*] Modo Taint-Only (apenas inputs rastreados): " . ($taintOnly ? "ATIVADO" : "DESATIVADO") . "\n");
fwrite(STDERR, "[*] Arquivos PHP encontrados: {$totalFiles}\n");
fwrite(STDERR, "[*] Motor de Execução: " . ($canUseSwoole ? "Swoole Multi-Process ({$workers} workers paralelos)" : "Sequencial (1 processo)") . "\n");

$filesWithFindings = [];
$parseErrors = [];

if ($canUseSwoole) {
    $actualWorkers = min($workers, $totalFiles);
    $chunks = array_chunk($allPhpFiles, (int)ceil($totalFiles / $actualWorkers));

    // Usa /dev/shm (RAM disk no Linux) se disponível para IPC ultra-rápido sem limite de buffer de pipe
    $ipcDir = (is_dir('/dev/shm') && is_writable('/dev/shm')) ? '/dev/shm' : sys_get_temp_dir();
    $ipcFiles = [];
    $childPids = [];

    foreach ($chunks as $idx => $chunk) {
        $tmpFile = $ipcDir . '/ast_swoole_worker_' . getmypid() . '_' . $idx . '.ser';
        $ipcFiles[$idx] = $tmpFile;

        $process = new \Swoole\Process(function (\Swoole\Process $worker) use (
            $chunk,
            $targetPath,
            $taintOnly,
            $taintParams,
            $captureAllCalls,
            $tmpFile
        ) {
            $batchResult = analyzeFileBatch($chunk, $targetPath, $taintOnly, $taintParams, $captureAllCalls);
            file_put_contents($tmpFile, serialize($batchResult));
            $worker->exit(0);
        }, false, 0);

        $pid = $process->start();
        if ($pid !== false) {
            $childPids[$pid] = $idx;
        }
    }

    // Aguarda todos os workers terminarem
    while (!empty($childPids)) {
        $status = \Swoole\Process::wait(true);
        if ($status !== false && isset($childPids[$status['pid']])) {
            unset($childPids[$status['pid']]);
        }
    }

    // Consolida os resultados da memória compartilhada
    foreach ($ipcFiles as $tmpFile) {
        if (is_file($tmpFile)) {
            $raw = file_get_contents($tmpFile);
            @unlink($tmpFile);
            if ($raw !== false) {
                $data = @unserialize($raw);
                if (is_array($data)) {
                    foreach ($data['files'] ?? [] as $f) {
                        $filesWithFindings[] = $f;
                    }
                    foreach ($data['parse_errors'] ?? [] as $e) {
                        $parseErrors[] = $e;
                    }
                }
            }
        }
    }

    // Mantém a ordenação determinística por nome de arquivo
    usort($filesWithFindings, static fn(array $a, array $b) => $a['file'] <=> $b['file']);
} else {
    $result = analyzeFileBatch($allPhpFiles, $targetPath, $taintOnly, $taintParams, $captureAllCalls);
    $filesWithFindings = $result['files'];
    $parseErrors       = $result['parse_errors'];
}

$summaryByCategory = [
    'RCE'           => 0,
    'FILE_WRITE'    => 0,
    'SQL_INJECTION' => 0,
];
$totalFindings = 0;

foreach ($filesWithFindings as $fileEntry) {
    foreach ($fileEntry['matches'] as $f) {
        $summaryByCategory[$f['category']] = ($summaryByCategory[$f['category']] ?? 0) + 1;
        $totalFindings++;
    }
}

$elapsedSeconds = round(microtime(true) - $startTime, 3);

$outputPayload = [
    'metadata' => [
        'engine'              => 'nikic/php-parser AST + Multi-Framework Taint Tracker',
        'parallel_engine'     => $canUseSwoole ? "swoole_process_pool ({$workers} workers)" : 'single_process',
        'elapsed_seconds'     => $elapsedSeconds,
        'scanned_path'        => $targetPath,
        'excluded_dirs'       => $excludeDirs,
        'taint_only_mode'     => $taintOnly,
        'taint_params_mode'   => $taintParams,
        'total_php_files'     => $totalFiles,
        'flagged_files_count' => count($filesWithFindings),
        'total_sinks_found'   => $totalFindings,
        'counts_by_category'  => $summaryByCategory,
        'parse_errors_count'  => count($parseErrors),
        'generated_at'        => date('c'),
    ],
    'files'        => $filesWithFindings,
    'parse_errors' => $parseErrors,
];

$jsonResult = json_encode(
    $outputPayload,
    JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE
);

fwrite(STDERR, "[✓] Tempo de análise: {$elapsedSeconds}s\n");

if (!empty($options['out'])) {
    $bytes = file_put_contents((string)$options['out'], $jsonResult);
    fwrite(STDERR, "[✓] Concluído! {$totalFindings} vulnerabilidades rastreadas em " . count($filesWithFindings) . " arquivo(s).\n");
    fwrite(STDERR, "[✓] Salvo em: {$options['out']} ({$bytes} bytes)\n");
} else {
    echo $jsonResult . PHP_EOL;
}
