<?php

declare(strict_types=1);

/**
 * lightweight library for manage mikrotik with api
 *
 * @version 0.0.1
 * @author Mr Afaz
 * @package MikroLink
 * @copyright Copyright 2024 MikrotikMng library
 * @license https://opensource.org/licenses/MIT
 * @link https://github.com/imafaz/MikroLink
 */



namespace MikrotikApi;

use EasyLog\Logger;
use RuntimeException;

/**
 * @method void __construct(bool $debug = false, int $timeout = 1,  int $attempts = 3,int  $delay = 0)
 * @method bool connect(string $ip, string $username, string $password, int $port, $ssl = false)
 * @method array read(true)
 * @method bool write(string $command, $param2 = true)
 * @method mixed encodeLength(mixed $length)
 * @method void disconnect()
 * @method mixed parseResponse(mixed $response)
 * @method void debug(string $text)
 * @method void __destruct()
 * @method array exec(string $command, array $params = null)
 */


class MikroLink
{

    /**
     * debuging var
     *
     * @var bool
     */
    var $debug;


    /**
     * connected to mikrotik var
     *
     * @var bool
     */
    var $connected = false;


    /**
     * ssl var
     *
     * @var bool
     */
    var $ssl;

    
    /**
     * socket object
     *
     * @var object
     */
    var $socket;



       /**
     * socket error number
     *
     * @var int
     */
    var $error_no;



       /**
     * socket error string
     *
     * @var sttring
     */
    var $error_str;


       /**
     * mikrotik router port (ssl or not)
     *
     * @var int
     */
    var $port;


       /**
     * time out connect to router
     *
     * @var int
     */
    var $timeout;


       /**
     * try connect count
     *
     * @var int
     */
    var $attempts;

    
    /**
     * delay after connected
     *
     * @var int
     */
    var $delay;


    
    
    /**
     * loggger object
     *
     * @var object
     */
    private $logger;
    


    /**
     * __construct: init options
     * 
     * @param  bool $debug
     * @param  int $timeout
     * @param  int $attempts
     * @param  int $delay
     * 
     * @return void
     */
    public function __construct( int $timeout = 1,  int $attempts = 3,int  $delay = 0,$logFile = 'mikrolink.log',$printLog = false)
    {
        $this->logger = new Logger($logFile, $printLog);
        $this->timeout = $timeout;
        $this->attempts = $attempts;
        $this->delay = $delay;
    }

    /**
     * connect: connect and login to mikrotik
     * 
     * @param  string $ip
     * @param  string $username
     * @param  string $password
     * @param  int $port
     * @param  bool $ssl
     * 
     * @return bool
     */
    public function connect(string $ip, string $username, string $password, int $port,bool  $ssl = false)
    {

        for ($ATTEMPT = 1; $ATTEMPT <= $this->attempts; $ATTEMPT++) {
            $this->connected = false;
            $PROTOCOL = ($ssl ? 'ssl://' : '');
            $context = stream_context_create(array('ssl' => array('ciphers' => 'ADH:ALL', 'verify_peer' => false, 'verify_peer_name' => false)));
            $this->logger->debug('Connection attempt #' . $ATTEMPT . ' to ' . $PROTOCOL . $ip . ':' . $port . '...');
            $this->socket = @stream_socket_client($PROTOCOL . $ip . ':' . $port, $this->error_no, $this->error_str, $this->timeout, STREAM_CLIENT_CONNECT, $context);
            if ($this->socket) {
                socket_set_timeout($this->socket, $this->timeout);
                $this->write('/login', false);
                $this->write('=name=' . $username, false);
                $this->write('=password=' . $password);
                $RESPONSE = $this->readLoginResponse();
                if (isset($RESPONSE[0])) {
                    if ($RESPONSE[0] == '!done') {
                        if (!isset($RESPONSE[1])) {
                            // Login method post-v6.43
                            $this->connected = true;
                            break;
                        } else {
                            // Login method pre-v6.43
                            $MATCHES = array();
                            if (preg_match_all('/[^=]+/i', $RESPONSE[1], $MATCHES)) {
                                if ($MATCHES[0][0] == 'ret' && strlen($MATCHES[0][1]) == 32) {
                                    $this->write('/login', false);
                                    $this->write('=name=' . $username, false);
                                    $this->write('=response=00' . md5(chr(0) . $password . pack('H*', $MATCHES[0][1])));
                                    $RESPONSE = $this->readLoginResponse();
                                    if (isset($RESPONSE[0]) && $RESPONSE[0] == '!done') {
                                        $this->connected = true;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
                if (is_resource($this->socket)) {
                    fclose($this->socket);
                }
            }
            sleep($this->delay);
        }

        if ($this->connected) {
            $this->logger->debug('Connected...');
        } else {
            $this->logger->error($this->error_str);
        }
        return $this->connected;
    }


    /**
     * read: read mikrotik api socket
     * 
     * @param  bool $parse
     * 
     * @return array
     * @throws RuntimeException If the socket cannot deliver a complete reply.
     */
    public function read(bool $parse = true)
    {
        if (!is_resource($this->socket)) {
            throw new RuntimeException('RouterOS API socket is not open.');
        }

        $response = [];
        $sentence = [];

        while (true) {
            $length = $this->readWordLength();
            if ($length > 0) {
                $sentence[] = $this->readBytes($length);
                $this->logger->debug('>>> [' . $length . '] bytes read.');
                continue;
            }

            if ($sentence === []) {
                continue;
            }

            $type = $sentence[0];
            if (!$parse || $type !== '!empty') {
                foreach ($sentence as $word) {
                    $response[] = $word;
                }
            }

            if ($type === '!done') {
                break;
            }
            if ($type === '!fatal') {
                $this->disconnect();
                break;
            }

            $sentence = [];
        }

        return $parse ? $this->parseResponse($response) : $response;
    }

    private function readLoginResponse(): array
    {
        try {
            return $this->read(false);
        } catch (RuntimeException $error) {
            $this->error_str = $error->getMessage();
            return [];
        }
    }

    private function readWordLength(): int
    {
        $first = ord($this->readBytes(1));
        if ($first < 0x80) {
            return $first;
        }

        [$length, $remaining] = match (true) {
            $first < 0xC0 => [$first & 0x3F, 1],
            $first < 0xE0 => [$first & 0x1F, 2],
            $first < 0xF0 => [$first & 0x0F, 3],
            $first === 0xF0 => [0, 4],
            default => $this->failRead('RouterOS API sent an unsupported word length prefix.'),
        };

        $suffix = $this->readBytes($remaining);
        for ($i = 0; $i < $remaining; $i++) {
            $length = ($length << 8) | ord($suffix[$i]);
        }

        return $length;
    }

    private function readBytes(int $length): string
    {
        $data = '';
        while (strlen($data) < $length) {
            $chunk = @fread($this->socket, min($length - strlen($data), 8192));
            if ($chunk === false || $chunk === '') {
                $status = stream_get_meta_data($this->socket);
                if ($status['timed_out']) {
                    $this->failRead('RouterOS API read timed out before the response completed.');
                }
                if ($status['eof']) {
                    $this->failRead('Unexpected EOF before the RouterOS API response completed.');
                }

                $this->failRead('Unable to read from the RouterOS API socket.');
            }

            $data .= $chunk;
        }

        return $data;
    }

    private function failRead(string $message): void
    {
        $this->disconnect();
        throw new RuntimeException($message);
    }

    /**
     * write: write in mikrotik api socket
     * 
     * @param  string $command
     * @param  bool|int $param2
     * 
     * @return bool
     */
    public function write(string $command,bool|int $param2 = true)
    {
        if ($command) {
            if (!is_resource($this->socket)) {
                throw new RuntimeException('RouterOS API socket is not open.');
            }

            $data = explode("\n", $command);
            foreach ($data as $com) {
                $com = trim($com);
                fwrite($this->socket, $this->encodeLength(strlen($com)) . $com);
                $this->logger->debug('<<< [' . strlen($com) . '] ' . $com);
            }

            if (gettype($param2) == 'integer') {
                fwrite($this->socket, $this->encodeLength(strlen('.tag=' . $param2)) . '.tag=' . $param2 . chr(0));
                $this->logger->debug('<<< [' . strlen('.tag=' . $param2) . '] .tag=' . $param2);
            } elseif (gettype($param2) == 'boolean') {
                fwrite($this->socket, ($param2 ? chr(0) : ''));
            }

            return true;
        } else {
            return false;
        }
    }



    /**
     * encodeLength: encodes a length value into a specific binary format
     * 
     * @param  mixed $length
     * 
     * @return mixed
     */
    public function encodeLength(mixed $length)
    {
        if ($length < 0x80) {
            $length = chr($length);
        } elseif ($length < 0x4000) {
            $length |= 0x8000;
            $length = chr(($length >> 8) & 0xFF) . chr($length & 0xFF);
        } elseif ($length < 0x200000) {
            $length |= 0xC00000;
            $length = chr(($length >> 16) & 0xFF) . chr(($length >> 8) & 0xFF) . chr($length & 0xFF);
        } elseif ($length < 0x10000000) {
            $length |= 0xE0000000;
            $length = chr(($length >> 24) & 0xFF) . chr(($length >> 16) & 0xFF) . chr(($length >> 8) & 0xFF) . chr($length & 0xFF);
        } elseif ($length >= 0x10000000) {
            $length = chr(0xF0) . chr(($length >> 24) & 0xFF) . chr(($length >> 16) & 0xFF) . chr(($length >> 8) & 0xFF) . chr($length & 0xFF);
        }

        return $length;
    }


    /**
     * disconnect: drop socket
     * 
     * @param  mixed $length
     * 
     * @return void
     */
    public function disconnect()
    {
        if (is_resource($this->socket)) {
            fclose($this->socket);
        }
        $this->connected = false;
        $this->logger->debug('Disconnected...');
    }


    /**
     * parseResponse:  extracting and organizing data based mikrotik
     * 
     * @param  mixed $response
     * 
     * @return array
     */
    public function parseResponse(mixed $response)
    {
        if (is_array($response)) {
            $PARSED      = array();
            $CURRENT     = null;
            $singlevalue = null;
            foreach ($response as $x) {
                if (in_array($x, array('!fatal', '!re', '!trap'))) {
                    if ($x == '!re') {

                        $PARSED[] = [];

                        $CURRENT = &$PARSED[count($PARSED) - 1];
                    } else {

                        if (!isset($PARSED[$x])) {

                            $PARSED[$x] = [];
                        }

                        $CURRENT = &$PARSED[$x];
                    }
                } elseif ($x != '!done') {
                    $MATCHES = array();
                    if (preg_match_all('/[^=]+/i', $x, $MATCHES)) {
                        if ($MATCHES[0][0] == 'ret') {
                            $singlevalue = $MATCHES[0][1];
                        }
                        $CURRENT[$MATCHES[0][0]] = (isset($MATCHES[0][1]) ? $MATCHES[0][1] : '');
                    }
                }
            }

            if (empty($PARSED) && !is_null($singlevalue)) {
                $PARSED = $singlevalue;
            }

            return $PARSED;
        } else {
            return array();
        }
    }

    /**
     * __destruct: disconnect after 
     * 
     * @return void
     */
    public function __destruct()
    {
        $this->disconnect();
    }


    /**
     * exec: execute command with parse response
     * 
     * @param  string $command
     * @param  array|null $params = null
     * 
     * @return array
     */
    public function exec(string $command, array|null $params = null)
    {
        if (is_array($params)) {
            $count = count($params);
            $this->write($command, !$params);
            $i = 0;
            foreach ($params as $k => $v) {
                switch ($k[0]) {
                    case "?":
                        $el = "$k=$v";
                        break;
                    case "~":
                        $el = "$k~$v";
                        break;
                    default:
                        $el = "=$k=$v";
                        break;
                }

                $last = ($i++ == $count - 1);
                $this->write($el, $last);
            }

            return $this->read();
        } else {
            $this->write($command);
            return $this->read();
        }
    }
}
