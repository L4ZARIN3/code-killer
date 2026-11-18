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

$defaultExcludes = ['.git', '.svn', '.idea', '.vscode', 'storage/framework', 'var/cache', 'runtime', 'tests', 'Test'];
$userExcludes = isset($options['exclude']) && $options['exclude'] !== ''
    ? array_map('trim', explode(',', (string)$options['exclude']))
    : ['vendor', 'node_modules'];

$excludeDirs = array_values(array_unique(array_filter(array_merge($defaultExcludes, $userExcludes))));

// ============================================================================
// CONFIGURAÇÕES GLOBAIS DE FONTES, SANITIZADORES E SINKS (PHP)
// ============================================================================
final class SecurityRules
{
    /** Superglobais que representam entrada direta do usuário */
    public const USER_SUPERGLOBALS = [
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
    public const TAINTED_SERVER_KEYS = [
        'QUERY_STRING',
        'REQUEST_URI',
        'PATH_INFO',
        'PHP_SELF',
        'HTTP_USER_AGENT',
        'HTTP_REFERER',
        'HTTP_HOST',
        'HTTP_ACCEPT',
        'HTTP_ACCEPT_LANGUAGE',
        'HTTP_X_FORWARDED_FOR',
        'HTTP_X_FORWARDED_HOST',
        'HTTP_CLIENT_IP',
        'HTTP_ORIGIN',
        'CONTENT_TYPE',
    ];

    /**
     * Funções nativas que representam Sinks perigosos e os ÍNDICES EXATOS
     * dos argumentos que precisam estar contaminados para gerar a falha.
     * Evita falsos positivos como marcar `$conn` em `mysqli_query($conn, 'SELECT 1')`.
     */
    public const NATIVE_SINKS = [
        'RCE' => [
            'eval'                      => [0],
            'assert'                    => [0],
            'create_function'           => [0, 1],
            'call_user_func'            => [0],
            'call_user_func_array'      => [0],
            'forward_static_call'       => [0],
            'forward_static_call_array' => [0],
            'register_shutdown_function'=> [0],
            'register_tick_function'    => [0],
            'array_map'                 => [0],
            'array_filter'              => [1],
            'array_walk'                => [1],
            'array_walk_recursive'      => [1],
            'usort'                     => [1],
            'uasort'                    => [1],
            'uksort'                    => [1],
            'preg_replace_callback'     => [1],
        ],
        'CMD_INJECTION' => [
            'system'                    => [0],
            'exec'                      => [0],
            'shell_exec'                => [0],
            'passthru'                  => [0],
            'popen'                     => [0],
            'proc_open'                 => [0],
            'pcntl_exec'                => [0],
        ],
        'SQL_INJECTION' => [
            'mysqli_query'              => [1],
            'mysqli_multi_query'        => [1],
            'mysqli_real_query'         => [1],
            'mysqli_prepare'            => [1],
            'mysql_query'               => [0],
            'mysql_db_query'            => [1],
            'mysql_unbuffered_query'    => [0],
            'pg_query'                  => [-1], // Polimórfico: 1 arg = [0], 2+ args = [1]
            'pg_send_query'             => [-1], // Polimórfico: 1 arg = [0], 2+ args = [1]
            'pg_prepare'                => [-2], // Polimórfico: 2 args = [1], 3 args = [2]
            'sqlite_query'              => [-1],
            'sqlite_exec'               => [-1],
            'odbc_exec'                 => [1],
            'oci_parse'                 => [1],
            'sqlsrv_query'              => [1],
            'sqlsrv_prepare'            => [1],
            'ibase_query'               => [-1],
        ],
        'FILE_WRITE' => [
            'file_put_contents'         => [0, 1],
            'fwrite'                    => [1],
            'fputs'                     => [1],
            'move_uploaded_file'        => [1],
            'chmod'                     => [0],
            'chown'                     => [0],
            'chgrp'                     => [0],
            'unlink'                    => [0],
            'rmdir'                     => [0],
            'rename'                    => [0, 1],
            'copy'                      => [0, 1],
            'mkdir'                     => [0],
            'symlink'                   => [0, 1],
            'link'                      => [0, 1],
        ],
        'LFI_FILE_READ' => [
            'file_get_contents'         => [0],
            'readfile'                  => [0],
            'file'                      => [0],
            'fopen'                     => [0],
            'highlight_file'            => [0],
            'show_source'               => [0],
            'parse_ini_file'            => [0],
            'get_meta_tags'             => [0],
        ],
        'DESERIALIZATION' => [
            'unserialize'               => [0],
            'yaml_parse'                => [0],
            'yaml_parse_file'           => [0],
        ],
        'SSRF' => [
            'curl_init'                 => [0],
            'fsockopen'                 => [0],
            'pfsockopen'                => [0],
            'stream_socket_client'      => [0],
            'get_headers'               => [0],
        ],
        'XXE' => [
            'simplexml_load_string'     => [0],
            'simplexml_load_file'       => [0],
        ],
    ];

    /** Métodos de Frameworks que executam SQL cru (SQLi) */
    public const SQL_FRAMEWORK_METHODS = [
        'query'              => [0],
        'exec'               => [0],
        'prepare'            => [0],
        'rawquery'           => [0],
        'fetchall'           => [0],
        'raw'                => [0],
        'selectraw'          => [0],
        'whereraw'           => [0],
        'orwhereraw'         => [0],
        'havingraw'          => [0],
        'orhavingraw'        => [0],
        'orderbyraw'         => [0],
        'groupbyraw'         => [0],
        'fromraw'            => [0],
        'unprepared'         => [0],
        'statement'          => [0],
        'select'             => [0],
        'affectingstatement' => [0],
        'createquery'        => [0],
        'executequery'       => [0],
        'executestatement'   => [0],
        'executeupdate'      => [0],
        'createcommand'      => [0],
        'findbysql'          => [0],
    ];

    /** Métodos de Frameworks que causam RCE / Command Injection */
    public const CMD_FRAMEWORK_METHODS = [
        'fromshellcommandline' => [0],
        'command'              => [0],
    ];

    /** Métodos de Frameworks que gravam/movem/extraem arquivos */
    public const FILE_FRAMEWORK_METHODS = [
        'put'       => [0, 1],
        'putfileas' => [0, 2],
        'move'      => [0, 1],
        'storeas'   => [0, 1],
        'moveto'    => [0],
        'dumpfile'  => [0, 1],
        'extractto' => [0],
    ];

    /** Métodos de Frameworks/Bibliotecas que causam SSRF */
    public const SSRF_FRAMEWORK_METHODS = [
        'request'     => [1], // Guzzle $client->request('GET', $url)
        'get'         => [0], // Http::get($url) / $guzzle->get($url)
        'post'        => [0],
        'put'         => [0],
        'delete'      => [0],
        'patch'       => [0],
    ];

    /** Métodos de XML que causam XXE */
    public const XXE_METHODS = [
        'loadxml'    => [0], // DOMDocument::loadXML
        'load'       => [0], // DOMDocument::load
        'xml'        => [0], // XMLReader::xml
        'open'       => [0], // XMLReader::open
    ];

    /** Sanitizadores Universais: convertem o dado para tipo primitivo seguro ou hash fixo */
    public const UNIVERSAL_SANITIZERS = [
        'intval',
        'floatval',
        'doubleval',
        'boolval',
        'count',
        'sizeof',
        'strlen',
        'mb_strlen',
        'md5',
        'sha1',
        'crc32',
        'hash',
        'hash_hmac',
        'password_hash',
        'base64_encode',
        'ctype_digit',
        'ctype_alnum',
        'ctype_alpha',
        'is_int',
        'is_integer',
        'is_long',
        'is_float',
        'is_double',
        'is_numeric',
        'is_bool',
        'abs',
        'round',
        'floor',
        'ceil',
        'max',
        'min',
        'strtotime',
        'mktime',
        'ip2long',
    ];

    /**
     * Sanitizadores específicos por categoria:
     * Evita que `escapeshellarg()` marque uma variável como segura para `SQL_INJECTION`
     * ou que `mysqli_real_escape_string()` marque como segura para `CMD_INJECTION`.
     */
    public const CATEGORY_SANITIZERS = [
        'CMD_INJECTION' => [
            'escapeshellarg',
            'escapeshellcmd',
        ],
        'SQL_INJECTION' => [
            'mysqli_real_escape_string',
            'mysqli_escape_string',
            'mysql_real_escape_string',
            'pg_escape_string',
            'pg_escape_literal',
            'pg_escape_identifier',
            'sqlite_escape_string',
        ],
        'FILE_WRITE' => [
            'basename',
        ],
        'LFI_FILE_READ' => [
            'basename',
        ],
        'SSRF' => [
            'urlencode',
            'rawurlencode',
        ],
    ];

    /**
     * Funções que retornam APENAS booleano ou posição numérica:
     * Nunca devem propagar taint quando recebem uma variável contaminada como argumento!
     */
    public const NON_PROPAGATING_FUNCTIONS = [
        'isset',
        'empty',
        'in_array',
        'array_key_exists',
        'key_exists',
        'strpos',
        'stripos',
        'strrpos',
        'strripos',
        'mb_strpos',
        'mb_stripos',
        'str_contains',
        'str_starts_with',
        'str_ends_with',
        'preg_match',
        'preg_match_all',
        'strcmp',
        'strcasecmp',
        'strncmp',
        'strncasecmp',
        'version_compare',
        'hash_equals',
        ' file_exists',
        'file_exists',
        'is_file',
        'is_dir',
        'is_readable',
        'is_writable',
        'is_uploaded_file',
        'defined',
        'function_exists',
        'class_exists',
        'method_exists',
        'property_exists',
    ];

    /** Métodos de objetos Request nos principais Frameworks PHP */
    public const INPUT_METHODS = [
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
        'getdata',
        'getparam',
        'getparams',
        'getbodyparam',
        'getbodyparams',
        'getqueryparam',
        'getparameter',
        'getparameters',
    ];
}

// ============================================================================
// PASSO 1: PRÉ-SCANNER INTRA-ARQUIVO (Mapeia Retornos, Propriedades e Wrappers)
// ============================================================================
class IntraFileSummary
{
    /**
     * Funções/métodos que retornam diretamente uma fonte contaminada.
     * Ex: 'ClassName::getInput' => ['source' => '$_GET["x"]', 'line' => 15]
     * @var array<string, array{source: string, line: int}>
     */
    public array $taintedReturnMethods = [];

    /**
     * Funções/métodos que repassam o taint de um argumento para o `return`.
     * Ex: 'ClassName::clean' => [0, 1] (se arg 0 ou 1 for tainted, o retorno é tainted)
     * @var array<string, array<int, int>>
     */
    public array $passthroughMethods = [];

    /**
     * Propriedades de classe ($this->prop) que recebem input contaminado em qualquer método.
     * Ex: 'ClassName::$filtro' => ['source' => '$_POST["f"]', 'trace' => [...]]
     * @var array<string, array{source: string, trace: array<int, string>}>
     */
    public array $taintedProperties = [];
}

// ============================================================================
// PASSO 2: MOTOR PRINCIPAL DE TAINT ANALYSIS + DETECTOR MULTI-FRAMEWORK NA AST
// ============================================================================
class TaintAndSinkVisitor extends NodeVisitorAbstract
{
    private const INCLUDE_TYPES = [
        Node\Expr\Include_::TYPE_INCLUDE      => 'include',
        Node\Expr\Include_::TYPE_INCLUDE_ONCE => 'include_once',
        Node\Expr\Include_::TYPE_REQUIRE      => 'require',
        Node\Expr\Include_::TYPE_REQUIRE_ONCE => 'require_once',
    ];

    public array $findings = [];
    private array $funcLookup = [];
    private array $fileLines;
    private bool $taintOnly;
    private bool $taintParams;
    private bool $captureAllCalls;
    private bool $isPreScanPass;
    private IntraFileSummary $summary;
    private PrettyPrinter\Standard $printer;
    private NodeFinder $nodeFinder;
    private ?string $currentClassName = null;
    private ?string $currentMethodKey = null;
    private bool $isInsideControllerOrPresenter = false;

    /**
     * Mapa de parâmetros do método atual para índice (usado no Passo 1 para detectar passthrough)
     * @var array<string, int>
     */
    private array $currentMethodParamIndexes = [];

    /**
     * Pilha de escopos de Taint
     * @var array<int, array<string, array{source: string, trace: array<int, string>, sanitized_for: array<string, bool>}>>
     */
    private array $taintScopes = [[]];

    public function __construct(
        string $fileContent,
        bool $taintOnly,
        bool $taintParams,
        bool $captureAllCalls,
        IntraFileSummary $summary,
        bool $isPreScanPass = false
    ) {
        $this->fileLines       = explode("\n", $fileContent);
        $this->taintOnly       = $taintOnly;
        $this->taintParams     = $taintParams;
        $this->captureAllCalls = $captureAllCalls;
        $this->summary         = $summary;
        $this->isPreScanPass   = $isPreScanPass;
        $this->printer         = new PrettyPrinter\Standard();
        $this->nodeFinder      = new NodeFinder();

        foreach (SecurityRules::NATIVE_SINKS as $category => $functions) {
            foreach ($functions as $fn => $argIndexes) {
                $this->funcLookup[$fn] = [
                    'category' => $category,
                    'indexes'  => $argIndexes,
                ];
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
                || str_contains($combined, 'resource')
                || str_contains($combined, 'handler');
            return;
        }

        // ====================================================================
        // A1. GERENCIAMENTO DE ESCOPO (Funções / Métodos / Closures / ArrowFn)
        // ====================================================================
        if (
            $node instanceof Node\Stmt\Function_
            || $node instanceof Node\Stmt\ClassMethod
            || $node instanceof Node\Expr\Closure
            || $node instanceof Node\Expr\ArrowFunction
        ) {
            $newScope = ($node instanceof Node\Expr\ArrowFunction)
                ? ($this->taintScopes[count($this->taintScopes) - 1] ?? [])
                : [];

            $this->currentMethodParamIndexes = [];
            if ($node instanceof Node\Stmt\ClassMethod) {
                $this->currentMethodKey = strtolower(($this->currentClassName ?? 'global') . '::' . $node->name->toString());
            } elseif ($node instanceof Node\Stmt\Function_) {
                $this->currentMethodKey = strtolower('global::' . $node->name->toString());
            }

            // Closure com `use ($x)` propaga o taint das variáveis importadas
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

            $isPublicControllerAction = ($node instanceof Node\Stmt\ClassMethod)
                && $node->isPublic()
                && $this->isInsideControllerOrPresenter
                && !str_starts_with($node->name->toString(), '__');

            foreach ($node->getParams() as $idx => $param) {
                if ($param->var instanceof Node\Expr\Variable && is_string($param->var->name)) {
                    $pName = '$' . $param->var->name;
                    $this->currentMethodParamIndexes[$pName] = $idx;

                    if ($this->isPreScanPass) {
                        // No Passo 1 marcamos parâmetros com marcador sintético para descobrir métodos passthrough
                        $newScope[$pName] = [
                            'source'        => "__PARAM_{$idx}__",
                            'trace'         => [],
                            'sanitized_for' => [],
                        ];
                    } elseif ($this->taintParams || $isPublicControllerAction) {
                        if ($this->isSafeTypehint($param->type) || $this->isNonInputObjectTypehint($param->type)) {
                            continue;
                        }
                        $line = $param->getStartLine();
                        $origin = $isPublicControllerAction ? "route_param:{$pName}" : "param:{$pName}";
                        $newScope[$pName] = [
                            'source'        => $origin,
                            'trace'         => ["Linha {$line}: Parâmetro de entrada recebido ({$origin})"],
                            'sanitized_for' => [],
                        ];
                    }
                }
            }

            $this->taintScopes[] = $newScope;
            return;
        }

        // ====================================================================
        // A2. DETECÇÃO DE GUARD CLAUSES / WHITELISTS EM BLOCOS `if (...)`
        // ====================================================================
        if ($node instanceof Node\Stmt\If_) {
            $this->processIfGuardClauses($node);
        }

        // Suporte a `global $var;`
        if ($node instanceof Node\Stmt\Global_) {
            foreach ($node->vars as $gVar) {
                if ($gVar instanceof Node\Expr\Variable && is_string($gVar->name)) {
                    $vKey = '$' . $gVar->name;
                    if (isset($this->taintScopes[0][$vKey])) {
                        $t = $this->taintScopes[0][$vKey];
                        $this->setTaint($vKey, $t['source'], $t['trace'], $t['sanitized_for'] ?? []);
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
                if ($taintInfo !== null && !str_starts_with($taintInfo['source'], '__PARAM_')) {
                    $line = $node->getStartLine();
                    $trace = $taintInfo['trace'];
                    $trace[] = "Linha {$line}: extract() importou variáveis de {$taintInfo['source']} para o escopo";
                    $this->setTaint('$__EXTRACT_TAINTED__', $taintInfo['source'], $trace);
                }
            } elseif (($fn === 'parse_str' || $fn === 'mb_parse_str') && !empty($args)) {
                $taintInfo = $this->inspectExpressionTaint($args[0]->value);
                if ($taintInfo !== null && !str_starts_with($taintInfo['source'], '__PARAM_')) {
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
                                $this->setTaint($tKey, $rhsTaint['source'], $trace, $rhsTaint['sanitized_for'] ?? []);
                            }
                        }
                    }
                }
            } else {
                $targetKey = $this->resolveVariableKey($node->var);
                if ($targetKey !== null) {
                    if ($this->isUniversalSanitizer($node->expr)) {
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

                            $sanitizedFor = $rhsTaint['sanitized_for'] ?? [];
                            foreach ($this->detectSanitizedCategories($node->expr) as $cat) {
                                $sanitizedFor[$cat] = true;
                            }

                            $this->setTaint($targetKey, $rhsTaint['source'], $newTrace, $sanitizedFor);

                            // No Passo 1, registra propriedades de classe contaminadas ($this->prop)
                            if (
                                $this->isPreScanPass
                                && str_starts_with($targetKey, '$this->')
                                && !str_starts_with($rhsTaint['source'], '__PARAM_')
                            ) {
                                $propKey = ($this->currentClassName ?? 'global') . '::' . $targetKey;
                                $this->summary->taintedProperties[$propKey] = [
                                    'source' => $rhsTaint['source'],
                                    'trace'  => $newTrace,
                                ];
                            }
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
                            $this->setTaint($valKey, $exprTaint['source'], $newTrace, $exprTaint['sanitized_for'] ?? []);
                        }
                    }
                }
            }
        }

        // ====================================================================
        // B2. PASSO 1: RASTREAMENTO DE `return` EM FUNÇÕES/MÉTODOS AUXILIARES
        // ====================================================================
        if ($this->isPreScanPass) {
            if ($node instanceof Node\Stmt\Return_ && $node->expr !== null && $this->currentMethodKey !== null) {
                $retTaint = $this->inspectExpressionTaint($node->expr);
                if ($retTaint !== null) {
                    if (preg_match('/^__PARAM_(\d+)__$/', $retTaint['source'], $m)) {
                        $paramIdx = (int)$m[1];
                        $this->summary->passthroughMethods[$this->currentMethodKey][] = $paramIdx;
                    } else {
                        $this->summary->taintedReturnMethods[$this->currentMethodKey] = [
                            'source' => $retTaint['source'],
                            'line'   => $node->getStartLine(),
                        ];
                    }
                }
            }
            return;
        }

        // ====================================================================
        // C. VERIFICAÇÃO DE SINKS (SOMENTE NO PASSO 2)
        // ====================================================================

        // 1. eval()
        if ($node instanceof Node\Expr\Eval_) {
            $this->evaluateAndRecordSink($node, 'RCE', 'eval', [$node->expr]);
            return;
        }

        // 2. Backticks: `$cmd` (Equivalente a shell_exec)
        if ($node instanceof Node\Expr\ShellExec) {
            $this->evaluateAndRecordSink($node, 'CMD_INJECTION', 'backticks_shell_exec', $node->parts);
            return;
        }

        // 3. include / require
        if ($node instanceof Node\Expr\Include_) {
            $sinkName = self::INCLUDE_TYPES[$node->type] ?? 'include';
            $this->evaluateAndRecordSink($node, 'LFI_FILE_READ', $sinkName, [$node->expr]);
            return;
        }

        // 4. Instanciação de Classes Perigosas ou Classe Dinâmica: `new $userClass()` / `new SplFileObject($path)`
        if ($node instanceof Node\Expr\New_) {
            if (!$node->class instanceof Node\Name && !$node->class instanceof Node\Stmt\Class_) {
                $this->evaluateAndRecordSink($node, 'DESERIALIZATION', 'dynamic_new_class', [$node->class]);
                return;
            }
            if ($node->class instanceof Node\Name) {
                $classNameLower = strtolower($node->class->getLast());
                $args = $node->getArgs();
                if ($classNameLower === 'splfileobject' && isset($args[0])) {
                    $this->evaluateAndRecordSink($node, 'LFI_FILE_READ', 'new SplFileObject', [$args[0]->value]);
                    return;
                }
                if ($classNameLower === 'simplexmlelement' && isset($args[0])) {
                    $this->evaluateAndRecordSink($node, 'XXE', 'new SimpleXMLElement', [$args[0]->value]);
                    return;
                }
            }
        }

        // 5. Chamadas de funções globais ou Variable Functions (`$fn()`)
        if ($node instanceof Node\Expr\FuncCall) {
            // Variable function call: `$callback($arg)` onde `$callback` é controlado pelo usuário
            if (!$node->name instanceof Node\Name) {
                $this->evaluateAndRecordSink($node, 'RCE', 'variable_function_call', [$node->name]);
                return;
            }

            $funcName = strtolower($node->name->getLast());
            $args = $node->getArgs();

            // Caso especial: `curl_setopt($ch, CURLOPT_URL, $taintedUrl)`
            if ($funcName === 'curl_setopt' && isset($args[1], $args[2])) {
                $optCode = strtoupper($this->printer->prettyPrintExpr($args[1]->value));
                if (str_contains($optCode, 'CURLOPT_URL')) {
                    $this->evaluateAndRecordSink($node, 'SSRF', 'curl_setopt(CURLOPT_URL)', [$args[2]->value]);
                }
                return;
            }

            // Caso especial: `preg_replace` (apenas modificador /e ou regex inteira dinâmica)
            if ($funcName === 'preg_replace') {
                $relevantExprs = $this->getPregReplaceRelevantExprs($args);
                if (!empty($relevantExprs)) {
                    $this->evaluateAndRecordSink($node, 'RCE', 'preg_replace', $relevantExprs);
                }
                return;
            }

            if (!isset($this->funcLookup[$funcName])) {
                return;
            }

            $sinkMeta = $this->funcLookup[$funcName];
            $category = $sinkMeta['category'];
            $indexes  = $sinkMeta['indexes'];

            // Resolução de índices polimórficos (ex: pg_query($sql) vs pg_query($conn, $sql))
            $relevantExprs = $this->resolveNativeSinkArgs($args, $indexes);
            if (!empty($relevantExprs)) {
                $this->evaluateAndRecordSink($node, $category, $funcName, $relevantExprs);
            }
            return;
        }

        // 6. Chamadas de Métodos ou Estáticas (Frameworks, PDO, DOMDocument, Guzzle, etc.)
        if ($node instanceof Node\Expr\MethodCall || $node instanceof Node\Expr\StaticCall) {
            if (!$node->name instanceof Node\Identifier) {
                // Chamada de método variável: `$obj->$userMethod()`
                if ($node->name instanceof Node\Expr) {
                    $this->evaluateAndRecordSink($node, 'RCE', 'variable_method_call', [$node->name]);
                }
                return;
            }

            $methodName = strtolower($node->name->toString());
            $args = $node->getArgs();
            if (empty($args)) {
                return;
            }

            // 6.1 Sinks de SQL Injection em Frameworks/ORMs/PDO
            if (isset(SecurityRules::SQL_FRAMEWORK_METHODS[$methodName])) {
                $sinkLabel = $this->resolveFrameworkSinkLabel($node, $methodName, 'SQL');
                if ($sinkLabel !== null) {
                    $relevantArgs = $this->extractArgIndexes($args, SecurityRules::SQL_FRAMEWORK_METHODS[$methodName]);
                    $this->evaluateAndRecordSink($node, 'SQL_INJECTION', $sinkLabel, $relevantArgs);
                    return;
                }
            }

            // 6.2 Sinks de Command Injection em Frameworks
            if (isset(SecurityRules::CMD_FRAMEWORK_METHODS[$methodName])) {
                $sinkLabel = $this->resolveFrameworkSinkLabel($node, $methodName, 'CMD');
                if ($sinkLabel !== null) {
                    $relevantArgs = $this->extractArgIndexes($args, SecurityRules::CMD_FRAMEWORK_METHODS[$methodName]);
                    $this->evaluateAndRecordSink($node, 'CMD_INJECTION', $sinkLabel, $relevantArgs);
                    return;
                }
            }

            // 6.3 Sinks de Escrita/Upload/Extração de Arquivos em Frameworks
            if (isset(SecurityRules::FILE_FRAMEWORK_METHODS[$methodName])) {
                $sinkLabel = $this->resolveFrameworkSinkLabel($node, $methodName, 'FILE');
                if ($sinkLabel !== null) {
                    $relevantArgs = $this->extractArgIndexes($args, SecurityRules::FILE_FRAMEWORK_METHODS[$methodName]);
                    $this->evaluateAndRecordSink($node, 'FILE_WRITE', $sinkLabel, $relevantArgs);
                    return;
                }
            }

            // 6.4 Sinks de SSRF em Frameworks (Laravel Http::get/post, Guzzle)
            if (isset(SecurityRules::SSRF_FRAMEWORK_METHODS[$methodName])) {
                $sinkLabel = $this->resolveFrameworkSinkLabel($node, $methodName, 'SSRF');
                if ($sinkLabel !== null) {
                    $relevantArgs = $this->extractArgIndexes($args, SecurityRules::SSRF_FRAMEWORK_METHODS[$methodName]);
                    $this->evaluateAndRecordSink($node, 'SSRF', $sinkLabel, $relevantArgs);
                    return;
                }
            }

            // 6.5 Sinks de XXE (DOMDocument::loadXML, XMLReader::xml)
            if (isset(SecurityRules::XXE_METHODS[$methodName])) {
                $sinkLabel = $this->resolveFrameworkSinkLabel($node, $methodName, 'XXE');
                if ($sinkLabel !== null) {
                    $relevantArgs = $this->extractArgIndexes($args, SecurityRules::XXE_METHODS[$methodName]);
                    $this->evaluateAndRecordSink($node, 'XXE', $sinkLabel, $relevantArgs);
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
            if ($node instanceof Node\Stmt\Function_ || $node instanceof Node\Stmt\ClassMethod) {
                $this->currentMethodKey = null;
                $this->currentMethodParamIndexes = [];
            }
        }
    }

    /**
     * Resolve índices de argumentos para funções nativas, incluindo funções polimórficas (ex: pg_query).
     * @param array<int, Node\Arg> $args
     * @param array<int, int> $indexes
     * @return array<int, Node\Expr>
     */
    private function resolveNativeSinkArgs(array $args, array $indexes): array
    {
        if ($indexes === [-1]) {
            // Se 1 argumento: arg[0] é a query; se 2+ argumentos: arg[0] é conexão e arg[1] é a query
            if (count($args) === 1) {
                return [$args[0]->value];
            }
            return isset($args[1]) ? [$args[1]->value] : [];
        }

        if ($indexes === [-2]) {
            // pg_prepare: 2 args -> arg[1] é query; 3 args -> arg[2] é query
            if (count($args) === 2) {
                return [$args[1]->value];
            }
            return isset($args[2]) ? [$args[2]->value] : [];
        }

        return $this->extractArgIndexes($args, $indexes);
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
            $foundTaint = $this->inspectExpressionTaint($expr, $category);
            if ($foundTaint !== null && !str_starts_with($foundTaint['source'], '__PARAM_')) {
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
            $traceSteps[] = "Linha {$line}: Chegou ao Sink ({$category}) `{$this->shortenCode($this->printer->prettyPrintExpr($sinkNode))}`";
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
     * Inspeciona recursivamente uma expressão podando galhos que possuem sanitizadores,
     * expressões booleanas ou condições de ternário/match.
     */
    private function inspectExpressionTaint(Node $expr, ?string $targetCategory = null): ?array
    {
        // 1. Se este nó é um sanitizador universal ou expressão puramente booleana, poda aqui!
        if ($this->isUniversalSanitizer($expr) || $this->isBooleanOrComparisonExpression($expr)) {
            return null;
        }

        // 2. Se estamos avaliando um Sink de categoria específica e este nó sanitiza essa categoria, poda aqui!
        if ($targetCategory !== null && $this->isCategorySanitizer($expr, $targetCategory)) {
            return null;
        }

        // 3. Verifica se o próprio nó atual é uma fonte direta de input (ou método que retorna input)
        $direct = $this->checkSingleNodeDirectSource($expr);
        if ($direct !== null) {
            return $direct;
        }

        // 4. Verifica se o nó atual é uma variável/propriedade já marcada como Tainted
        if (
            $expr instanceof Node\Expr\Variable
            || $expr instanceof Node\Expr\PropertyFetch
            || $expr instanceof Node\Expr\ArrayDimFetch
        ) {
            // Se for acesso a índice de array `$whitelist[$input]`, só propaga se a base `$whitelist` for tainted ou superglobal!
            if ($expr instanceof Node\Expr\ArrayDimFetch) {
                $baseKey = $this->resolveVariableKey($expr->var);
                if ($baseKey !== null) {
                    $existingBase = $this->getTaint($baseKey, $targetCategory);
                    if ($existingBase !== null) {
                        return $existingBase;
                    }
                }
                return $this->inspectExpressionTaint($expr->var, $targetCategory);
            }

            $key = $this->resolveVariableKey($expr);
            if ($key !== null) {
                $existing = $this->getTaint($key, $targetCategory);
                if ($existing !== null) {
                    return $existing;
                }
                $extractTaint = $this->getTaint('$__EXTRACT_TAINTED__', $targetCategory);
                if ($extractTaint !== null && $expr instanceof Node\Expr\Variable) {
                    return $extractTaint;
                }
            }
        }

        // 5. Tratamento preciso de Operador Ternário ($cond ? $if : $else)
        // NUNCA inspeciona `$cond` quando `$if` existe, evitando falsos positivos como `isset($_GET['a']) ? '1' : '0'`
        if ($expr instanceof Node\Expr\Ternary) {
            if ($expr->if !== null) {
                return $this->inspectExpressionTaint($expr->if, $targetCategory)
                    ?? $this->inspectExpressionTaint($expr->else, $targetCategory);
            }
            // Operador Elvis ($a ?: $b)
            return $this->inspectExpressionTaint($expr->cond, $targetCategory)
                ?? $this->inspectExpressionTaint($expr->else, $targetCategory);
        }

        // 6. Tratamento preciso de `match ($cond) { ... }` (PHP 8): inspeciona apenas o retorno (`body`) de cada braço
        if ($expr instanceof Node\Expr\Match_) {
            foreach ($expr->arms as $arm) {
                $armTaint = $this->inspectExpressionTaint($arm->body, $targetCategory);
                if ($armTaint !== null) {
                    return $armTaint;
                }
            }
            return null;
        }

        // 7. Chamadas de métodos/funções customizadas do mesmo arquivo que são Passthrough
        if ($expr instanceof Node\Expr\MethodCall || $expr instanceof Node\Expr\FuncCall) {
            $calleeKey = $this->resolveInternalCalleeKey($expr);
            if ($calleeKey !== null && isset($this->summary->passthroughMethods[$calleeKey])) {
                $args = $expr->getArgs();
                foreach ($this->summary->passthroughMethods[$calleeKey] as $pIdx) {
                    if (isset($args[$pIdx])) {
                        $argTaint = $this->inspectExpressionTaint($args[$pIdx]->value, $targetCategory);
                        if ($argTaint !== null) {
                            return $argTaint;
                        }
                    }
                }
            }
        }

        // 8. Desce recursivamente pelos sub-nós da expressão
        foreach ($expr->getSubNodeNames() as $name) {
            $subNode = $expr->$name;
            if ($subNode instanceof Node) {
                if (
                    ($expr instanceof Node\Expr\FuncCall || $expr instanceof Node\Expr\MethodCall || $expr instanceof Node\Expr\StaticCall)
                    && ($name === 'name' || $name === 'class')
                ) {
                    continue;
                }
                $subTaint = $this->inspectExpressionTaint($subNode, $targetCategory);
                if ($subTaint !== null) {
                    return $subTaint;
                }
            } elseif (is_array($subNode)) {
                foreach ($subNode as $item) {
                    if ($item instanceof Node) {
                        $subTaint = $this->inspectExpressionTaint($item, $targetCategory);
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
     * Avalia se UM nó específico da AST é uma fonte de entrada (Superglobal, Request de Framework ou Método Interno)
     */
    private function checkSingleNodeDirectSource(Node $n): ?array
    {
        // Caso 1: $_GET['id'], $_POST['cmd'], $_SERVER['HTTP_...']
        if ($n instanceof Node\Expr\ArrayDimFetch) {
            $rootVar = $n;
            while ($rootVar instanceof Node\Expr\ArrayDimFetch) {
                $rootVar = $rootVar->var;
            }
            if ($rootVar instanceof Node\Expr\Variable && is_string($rootVar->name)) {
                $varName = $rootVar->name;

                if (in_array($varName, SecurityRules::USER_SUPERGLOBALS, true)) {
                    $code = $this->printer->prettyPrintExpr($n);
                    $line = $n->getStartLine();
                    return [
                        'source'        => $code,
                        'trace'         => ["Linha {$line}: Input direto capturado de `{$code}`"],
                        'sanitized_for' => [],
                    ];
                }

                if ($varName === '_SERVER' && $n->dim instanceof Node\Scalar\String_) {
                    $srvKey = strtoupper($n->dim->value);
                    if (str_starts_with($srvKey, 'HTTP_') || in_array($srvKey, SecurityRules::TAINTED_SERVER_KEYS, true)) {
                        $code = $this->printer->prettyPrintExpr($n);
                        $line = $n->getStartLine();
                        return [
                            'source'        => $code,
                            'trace'         => ["Linha {$line}: Cabeçalho/URI HTTP capturado de `{$code}`"],
                            'sanitized_for' => [],
                        ];
                    }
                }
            }
        }

        // Caso 2: Superglobal acessada inteira ($_GET, $_POST)
        if ($n instanceof Node\Expr\Variable && is_string($n->name)) {
            if (in_array($n->name, SecurityRules::USER_SUPERGLOBALS, true)) {
                $code = '$' . $n->name;
                $line = $n->getStartLine();
                return [
                    'source'        => $code,
                    'trace'         => ["Linha {$line}: Superglobal `{$code}` acessada diretamente"],
                    'sanitized_for' => [],
                ];
            }
        }

        // Caso 3: Funções globais de input: getenv(), request('x'), filter_input(), file_get_contents('php://input')
        if ($n instanceof Node\Expr\FuncCall && $n->name instanceof Node\Name) {
            $fn = strtolower($n->name->getLast());
            $args = $n->getArgs();

            if (in_array($fn, ['getenv', 'getallheaders', 'apache_request_headers'], true)) {
                $code = $this->printer->prettyPrintExpr($n);
                $line = $n->getStartLine();
                return [
                    'source'        => $code,
                    'trace'         => ["Linha {$line}: Entrada externa lida via `{$code}`"],
                    'sanitized_for' => [],
                ];
            }

            if (in_array($fn, ['filter_input', 'filter_input_array', 'filter_var'], true)) {
                // Se usar FILTER_VALIDATE_INT / FLOAT / BOOLEAN ou FILTER_SANITIZE_NUMBER_INT, é seguro!
                $callCode = strtoupper($this->printer->prettyPrintExpr($n));
                if (
                    str_contains($callCode, 'VALIDATE_INT')
                    || str_contains($callCode, 'VALIDATE_FLOAT')
                    || str_contains($callCode, 'VALIDATE_BOOLEAN')
                    || str_contains($callCode, 'VALIDATE_BOOL')
                    || str_contains($callCode, 'SANITIZE_NUMBER_INT')
                ) {
                    return null;
                }
                if ($fn !== 'filter_var') {
                    $code = $this->printer->prettyPrintExpr($n);
                    $line = $n->getStartLine();
                    return [
                        'source'        => $code,
                        'trace'         => ["Linha {$line}: Entrada capturada via `{$code}` (sem filtro numérico estrito)"],
                        'sanitized_for' => [],
                    ];
                }
            }

            if ($fn === 'request' && !empty($args)) {
                $code = $this->printer->prettyPrintExpr($n);
                $line = $n->getStartLine();
                return [
                    'source'        => $code,
                    'trace'         => ["Linha {$line}: Helper `{$code}` (Laravel/Hyperf Request) capturado"],
                    'sanitized_for' => [],
                ];
            }

            if ($fn === 'file_get_contents' && !empty($args)) {
                $firstArg = $args[0]->value;
                if ($firstArg instanceof Node\Scalar\String_ && stripos($firstArg->value, 'php://input') !== false) {
                    $code = $this->printer->prettyPrintExpr($n);
                    $line = $n->getStartLine();
                    return [
                        'source'        => 'php://input',
                        'trace'         => ["Linha {$line}: Corpo da requisição HTTP lido via `{$code}`"],
                        'sanitized_for' => [],
                    ];
                }
            }
        }

        // Caso 4: Chamadas de método em objetos Request dos Frameworks OU métodos internos mapeados no Passo 1
        if ($n instanceof Node\Expr\MethodCall && $n->name instanceof Node\Identifier) {
            $mName = strtolower($n->name->toString());
            if (in_array($mName, SecurityRules::INPUT_METHODS, true)) {
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
                        'source'        => $code,
                        'trace'         => ["Linha {$line}: Input de Framework capturado via `{$code}`"],
                        'sanitized_for' => [],
                    ];
                }
            }

            // Verifica se é uma chamada `$this->metodoAuxiliar()` que retorna input contaminado (Passo 1)
            $calleeKey = $this->resolveInternalCalleeKey($n);
            if ($calleeKey !== null && isset($this->summary->taintedReturnMethods[$calleeKey])) {
                $info = $this->summary->taintedReturnMethods[$calleeKey];
                $code = $this->printer->prettyPrintExpr($n);
                $line = $n->getStartLine();
                return [
                    'source'        => $info['source'],
                    'trace'         => [
                        "Linha {$info['line']}: Método auxiliar `{$calleeKey}()` retorna `{$info['source']}`",
                        "Linha {$line}: Retorno contaminado recebido de `{$code}`",
                    ],
                    'sanitized_for' => [],
                ];
            }
        }

        // Caso 5: Facade estática `Request::input('x')`, `Request::get('x')`, `Request::all()`
        if ($n instanceof Node\Expr\StaticCall && $n->class instanceof Node\Name && $n->name instanceof Node\Identifier) {
            $className = strtolower($n->class->getLast());
            $mName = strtolower($n->name->toString());
            if ($className === 'request' && in_array($mName, SecurityRules::INPUT_METHODS, true)) {
                $code = $this->printer->prettyPrintExpr($n);
                $line = $n->getStartLine();
                return [
                    'source'        => $code,
                    'trace'         => ["Linha {$line}: Facade Request capturada via `{$code}`"],
                    'sanitized_for' => [],
                ];
            }
        }

        // Caso 6: Propriedade mágica no Laravel `$request->campo`
        if ($n instanceof Node\Expr\PropertyFetch && $n->var instanceof Node\Expr\Variable && $n->name instanceof Node\Identifier) {
            $varName = strtolower((string)$n->var->name);
            $propName = strtolower($n->name->toString());
            $symfonySubBags = ['query', 'request', 'attributes', 'cookies', 'files', 'server', 'headers'];

            if (($varName === 'request' || $varName === 'req') && !in_array($propName, $symfonySubBags, true)) {
                $code = $this->printer->prettyPrintExpr($n);
                $line = $n->getStartLine();
                return [
                    'source'        => $code,
                    'trace'         => ["Linha {$line}: Propriedade mágica de Request acessada via `{$code}`"],
                    'sanitized_for' => [],
                ];
            }
        }

        return null;
    }

    private function resolveInternalCalleeKey(Node\Expr $callNode): ?string
    {
        if (
            $callNode instanceof Node\Expr\MethodCall
            && $callNode->var instanceof Node\Expr\Variable
            && $callNode->var->name === 'this'
            && $callNode->name instanceof Node\Identifier
        ) {
            return strtolower(($this->currentClassName ?? 'global') . '::' . $callNode->name->toString());
        }
        if ($callNode instanceof Node\Expr\FuncCall && $callNode->name instanceof Node\Name) {
            return strtolower('global::' . $callNode->name->getLast());
        }
        return null;
    }

    private function isBooleanOrComparisonExpression(Node $expr): bool
    {
        if (
            $expr instanceof Node\Expr\Isset_
            || $expr instanceof Node\Expr\Empty_
            || $expr instanceof Node\Expr\Instanceof_
            || $expr instanceof Node\Expr\BooleanNot
            || $expr instanceof Node\Expr\BinaryOp\Identical
            || $expr instanceof Node\Expr\BinaryOp\NotIdentical
            || $expr instanceof Node\Expr\BinaryOp\Equal
            || $expr instanceof Node\Expr\BinaryOp\NotEqual
            || $expr instanceof Node\Expr\BinaryOp\Smaller
            || $expr instanceof Node\Expr\BinaryOp\SmallerOrEqual
            || $expr instanceof Node\Expr\BinaryOp\Greater
            || $expr instanceof Node\Expr\BinaryOp\GreaterOrEqual
            || $expr instanceof Node\Expr\BinaryOp\Spaceship
            || $expr instanceof Node\Expr\BinaryOp\BooleanAnd
            || $expr instanceof Node\Expr\BinaryOp\BooleanOr
            || $expr instanceof Node\Expr\BinaryOp\LogicalAnd
            || $expr instanceof Node\Expr\BinaryOp\LogicalOr
            || $expr instanceof Node\Expr\BinaryOp\LogicalXor
        ) {
            return true;
        }

        if ($expr instanceof Node\Expr\FuncCall && $expr->name instanceof Node\Name) {
            $fn = strtolower($expr->name->getLast());
            if (in_array($fn, SecurityRules::NON_PROPAGATING_FUNCTIONS, true)) {
                return true;
            }
        }

        return false;
    }

    private function isUniversalSanitizer(Node $expr): bool
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
            || $expr instanceof Node\Expr\BinaryOp\Mod
            || $expr instanceof Node\Expr\BinaryOp\Pow
            || $expr instanceof Node\Expr\BinaryOp\BitwiseAnd
            || $expr instanceof Node\Expr\BinaryOp\BitwiseOr
            || $expr instanceof Node\Expr\BinaryOp\BitwiseXor
            || $expr instanceof Node\Expr\BinaryOp\ShiftLeft
            || $expr instanceof Node\Expr\BinaryOp\ShiftRight
        ) {
            return true;
        }

        if ($expr instanceof Node\Expr\FuncCall && $expr->name instanceof Node\Name) {
            $fn = strtolower($expr->name->getLast());
            if (in_array($fn, SecurityRules::UNIVERSAL_SANITIZERS, true)) {
                return true;
            }
            // sprintf/vsprintf quando a string de formato só contém %d, %u, %f, %x, %b (sem %s)
            if (($fn === 'sprintf' || $fn === 'vsprintf') && !empty($expr->getArgs())) {
                $fmtArg = $expr->getArgs()[0]->value;
                if ($fmtArg instanceof Node\Scalar\String_ && !str_contains($fmtArg->value, '%s')) {
                    return true;
                }
            }
        }

        if ($expr instanceof Node\Expr\MethodCall && $expr->name instanceof Node\Identifier) {
            $mName = strtolower($expr->name->toString());
            if (in_array($mName, ['integer', 'boolean', 'float', 'getint', 'getboolean', 'getdigits'], true)) {
                return true;
            }
        }

        return false;
    }

    private function isCategorySanitizer(Node $expr, string $category): bool
    {
        $allowedFuncs = SecurityRules::CATEGORY_SANITIZERS[$category] ?? [];
        if ($expr instanceof Node\Expr\FuncCall && $expr->name instanceof Node\Name) {
            $fn = strtolower($expr->name->getLast());
            if (in_array($fn, $allowedFuncs, true)) {
                return true;
            }
        }

        // $pdo->quote($var) ou $db->escape($var) para SQL_INJECTION
        if ($category === 'SQL_INJECTION' && $expr instanceof Node\Expr\MethodCall && $expr->name instanceof Node\Identifier) {
            $mName = strtolower($expr->name->toString());
            if (in_array($mName, ['quote', 'escape', 'escapestring', 'real_escape_string'], true)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Identifica todas as categorias para as quais uma expressão foi sanitizada no momento da atribuição.
     * @return array<int, string>
     */
    private function detectSanitizedCategories(Node $expr): array
    {
        $categories = [];
        foreach ( array_keys(SecurityRules::CATEGORY_SANITIZERS) as $cat) {
            if ($this->isCategorySanitizer($expr, $cat)) {
                $categories[] = $cat;
            }
        }
        return $categories;
    }

    /**
     * Detecta Guard Clauses como:
     *   if (!in_array($col, ['id', 'nome'])) { return; }
     *   if (!ctype_digit($id)) { throw new Exception(); }
     * Descontaminando a variável após a validação.
     */
    private function processIfGuardClauses(Node\Stmt\If_ $ifNode): void
    {
        $hasTerminator = false;
        foreach ($ifNode->stmts as $stmt) {
            if (
                $stmt instanceof Node\Stmt\Return_
                || $stmt instanceof Node\Stmt\Throw_
                || ($stmt instanceof Node\Stmt\Expression && $stmt->expr instanceof Node\Expr\Exit_)
                || $stmt instanceof Node\Stmt\Continue_
                || $stmt instanceof Node\Stmt\Break_
            ) {
                $hasTerminator = true;
                break;
            }
        }

        if (!$hasTerminator) {
            return;
        }

        // Procura por `!in_array($var, ...)`, `!is_numeric($var)`, `!ctype_digit($var)`, `!preg_match(..., $var)`
        $negatedCalls = $this->nodeFinder->findInstanceOf($ifNode->cond, Node\Expr\BooleanNot::class);
        foreach ($negatedCalls as $notNode) {
            if ($notNode->expr instanceof Node\Expr\FuncCall && $notNode->expr->name instanceof Node\Name) {
                $fn = strtolower($notNode->expr->name->getLast());
                $args = $notNode->expr->getArgs();
                if (in_array($fn, ['in_array', 'is_numeric', 'is_int', 'ctype_digit', 'ctype_alnum', 'ctype_alpha'], true) && isset($args[0])) {
                    $vKey = $this->resolveVariableKey($args[0]->value);
                    if ($vKey !== null) {
                        $this->clearTaint($vKey);
                    }
                } elseif ($fn === 'preg_match' && isset($args[0], $args[1]) && $args[0]->value instanceof Node\Scalar\String_) {
                    $regex = $args[0]->value->value;
                    // Se a regex exige início ^ e fim $ restritos a caracteres alfanuméricos/dígitos
                    if (str_contains($regex, '^') && str_contains($regex, '$')) {
                        $vKey = $this->resolveVariableKey($args[1]->value);
                        if ($vKey !== null) {
                            $this->clearTaint($vKey);
                        }
                    }
                }
            }
        }
    }

    private function isSafeTypehint(?Node $typeNode): bool
    {
        if ($typeNode instanceof Node\Identifier) {
            return in_array(strtolower($typeNode->toString()), ['int', 'float', 'bool'], true);
        }
        return false;
    }

    private function isNonInputObjectTypehint(?Node $typeNode): bool
    {
        return $typeNode instanceof Node\Name;
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
            if (in_array($node->var->name, SecurityRules::USER_SUPERGLOBALS, true)) {
                return null;
            }
            return '$' . $node->var->name;
        }
        return null;
    }

    private function setTaint(string $key, string $source, array $trace, array $sanitizedFor = []): void
    {
        $currentIdx = count($this->taintScopes) - 1;
        $record = [
            'source'        => $source,
            'trace'         => $trace,
            'sanitized_for' => $sanitizedFor,
        ];
        $this->taintScopes[$currentIdx][$key] = $record;
        if (str_starts_with($key, '$this->')) {
            $this->taintScopes[0][$key] = $record;
        }
    }

    private function getTaint(string $key, ?string $targetCategory = null): ?array
    {
        $currentIdx = count($this->taintScopes) - 1;
        $found = null;

        if (isset($this->taintScopes[$currentIdx][$key])) {
            $found = $this->taintScopes[$currentIdx][$key];
        } elseif (str_starts_with($key, '$this->')) {
            if (isset($this->taintScopes[0][$key])) {
                $found = $this->taintScopes[0][$key];
            } else {
                $propKey = ($this->currentClassName ?? 'global') . '::' . $key;
                if (isset($this->summary->taintedProperties[$propKey])) {
                    $found = [
                        'source'        => $this->summary->taintedProperties[$propKey]['source'],
                        'trace'         => $this->summary->taintedProperties[$propKey]['trace'],
                        'sanitized_for' => [],
                    ];
                }
            }
        }

        if ($found !== null && $targetCategory !== null && !empty($found['sanitized_for'][$targetCategory])) {
            return null;
        }

        return $found;
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
            if (preg_match('/^([\/#~@%;!]).*\1[imsxeADSUXJu]*e[imsxeADSUXJu]*$/s', $patternExpr->value)) {
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
        if ($methodName === 'query' && $callNode instanceof Node\Expr\MethodCall) {
            $callerLower = strtolower($this->printer->prettyPrintExpr($callNode->var));
            if (
                str_contains($callerLower, 'request')
                || str_contains($callerLower, 'req')
                || str_contains($callerLower, 'input')
                || str_contains($callerLower, 'xpath')
                || str_contains($callerLower, 'dom')
            ) {
                return null;
            }
        }

        if ($callNode instanceof Node\Expr\StaticCall) {
            if ($callNode->class instanceof Node\Name) {
                $className = $callNode->class->toString();
                $classLower = strtolower($className);

                if ($type === 'SQL') {
                    $sqlStaticMethods = [
                        'whereraw', 'orwhereraw', 'selectraw', 'orderbyraw', 'havingraw',
                        'groupbyraw', 'fromraw', 'findbysql', 'raw', 'unprepared', 'statement',
                    ];
                    if (
                        str_contains($classLower, 'db')
                        || str_contains($classLower, 'pdo')
                        || in_array($methodName, $sqlStaticMethods, true)
                    ) {
                        return $className . '::' . $methodName;
                    }
                    return null;
                }

                if ($type === 'CMD') {
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

                if ($type === 'SSRF') {
                    if ($classLower === 'http' || str_contains($classLower, 'http') || str_contains($classLower, 'client')) {
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
                    || str_contains($callerLower, 'zip')
                    || str_contains($callerLower, 'phar')
                    || in_array($methodName, ['storeas', 'moveto', 'putfileas', 'extractto'], true)
                ) {
                    return $callerCode . '->' . $methodName;
                }
                return null;
            }

            if ($type === 'SSRF') {
                if (
                    str_contains($callerLower, 'http')
                    || str_contains($callerLower, 'guzzle')
                    || str_contains($callerLower, 'client')
                    || str_contains($callerLower, 'curl')
                ) {
                    return $callerCode . '->' . $methodName;
                }
                return null;
            }

            if ($type === 'XXE') {
                if (str_contains($callerLower, 'xml') || str_contains($callerLower, 'dom') || str_contains($callerLower, 'doc') || $methodName === 'loadxml') {
                    return $callerCode . '->' . $methodName;
                }
                return null;
            }

            if ($type === 'SQL' && in_array($methodName, ['select', 'prepare', 'exec', 'query'], true)) {
                if (
                    !str_contains($callerLower, 'db')
                    && !str_contains($callerLower, 'pdo')
                    && !str_contains($callerLower, 'conn')
                    && !str_contains($callerLower, 'sql')
                    && !str_contains($callerLower, 'database')
                    && !str_contains($callerLower, ' adapter')
                    && !str_contains($callerLower, 'entitymanager')
                    && $methodName === 'select'
                ) {
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

    /**
     * Extrai o código de contexto omitindo TODAS as linhas em branco ou que contenham
     * apenas espaços/tabs/quebras de linha, reduzindo o consumo de tokens para a IA.
     *
     * @return array<string, string>
     */
    private function extractLines(int $start, int $end): array
    {
        $slice = [];
        for ($i = $start; $i <= $end; $i++) {
            if (!isset($this->fileLines[$i - 1])) {
                continue;
            }

            $cleanedLine = rtrim($this->fileLines[$i - 1], "\r\n \t");

            // Garante que nenhuma linha vazia ("") ou só com espaços passe para o JSON
            if (trim($cleanedLine) === '') {
                continue;
            }

            $slice[(string)$i] = $cleanedLine;
        }
        return $slice;
    }
}

// ============================================================================
// VARREDURA DE DIRETÓRIOS (SOMENTE ARQUIVOS PHP)
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

            return in_array(strtolower($current->getExtension()), ['php', 'inc', 'phtml', 'php5', 'php7', 'php8', 'module'], true);
        }
    );

    foreach (new RecursiveIteratorIterator($filterIterator) as $fileInfo) {
        $files[] = $fileInfo->getPathname();
    }

    sort($files);
    return $files;
}

// ============================================================================
// FUNÇÃO DE PROCESSAMENTO DE UM LOTE DE ARQUIVOS (2-PASS ANALYSIS)
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

        $summary = new IntraFileSummary();

        // PASSO 1: Conecta nós pais e mapeia métodos auxiliares, retornos contaminados e propriedades da classe
        $preTraverser = new NodeTraverser();
        $preTraverser->addVisitor(new ParentConnectingVisitor());
        $preScanner = new TaintAndSinkVisitor($code, $taintOnly, $taintParams, $captureAllCalls, $summary, true);
        $preTraverser->addVisitor($preScanner);
        $preTraverser->traverse($ast);

        // PASSO 2: Executa a análise definitiva de Taint e Sinks usando o sumário do Passo 1
        $mainTraverser = new NodeTraverser();
        $visitor = new TaintAndSinkVisitor($code, $taintOnly, $taintParams, $captureAllCalls, $summary, false);
        $mainTraverser->addVisitor($visitor);
        $mainTraverser->traverse($ast);

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

    while (!empty($childPids)) {
        $status = \Swoole\Process::wait(true);
        if ($status !== false && isset($childPids[$status['pid']])) {
            unset($childPids[$status['pid']]);
        }
    }

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

    usort($filesWithFindings, static fn(array $a, array $b) => $a['file'] <=> $b['file']);
} else {
    $result = analyzeFileBatch($allPhpFiles, $targetPath, $taintOnly, $taintParams, $captureAllCalls);
    $filesWithFindings = $result['files'];
    $parseErrors       = $result['parse_errors'];
}

$summaryByCategory = [
    'RCE'             => 0,
    'CMD_INJECTION'   => 0,
    'SQL_INJECTION'   => 0,
    'LFI_FILE_READ'   => 0,
    'FILE_WRITE'      => 0,
    'DESERIALIZATION' => 0,
    'SSRF'            => 0,
    'XXE'             => 0,
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
        'engine'              => 'nikic/php-parser AST + 2-Pass Multi-Framework Taint Tracker',
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
