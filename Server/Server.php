<?php

spl_autoload_register(function ($class) 
{
	require_once $class.'.php';
});

require_once 'Test.php';

use Guzzle\Http\Message\RequestFactory;
use Ratchet\Wamp\WampServer;
use Ratchet\Server\IoServer;
use Ratchet\WebSocket\WsServer;
use MyApp\Test;

Test::log("Server gestartet!");

$oServer = IoServer::factory(new WsServer(new WampServer(new Test())), 8000);
$oServer->run();
