<?php
namespace MyApp;
use Ratchet\ConnectionInterface as Conn;
use Ratchet\Wamp\WampServerInterface;
use Ratchet\Wamp\Topic;

class Test implements WampServerInterface  
{
	private static $iClientCount = 0;
	
    public function onPublish(Conn $oConn, $oTopic, $aEvent, array $aExclude = array(), array $aEligible = array()) 
    {
	   switch ($oTopic->getID()) 
       {
	        case 'http://localhost/msg':
	        	self::log("Nachricht \"".$aEvent['data']."\" empfangen!");
	        break;
		    
		    case 'http://localhost/move': 
	        	self::log("Bewege Draggable-Element [".floatval($aEvent['left']).", ".floatval($aEvent['top'])."]");
	        break;
       }
       $oTopic->broadcast($aEvent); // Event an alle angemeldeten Clients verteilen.
    }

    public function onCall(Conn $oConn, $sID, $oFn, array $aParams) 
    {
       switch ($oFn->getId()) 
       {
	        case 'App:add': //App:add RPC
	        	self::log("Remote Procedure Call");
				return $oConn->callResult($sID, array('result' => intval($aParams[0])+intval($aParams[1]))); //Ausrechnen
	        break;
       }
    }

    public function onOpen(Conn $oConn) 
    {
    	self::$iClientCount++;
		self::log("Ein Client hat sich mit dem Server verbunden. Verbundene Clients: ".self::$iClientCount);
    }

    public function onClose(Conn $oConn) 
    {
    	self::$iClientCount--;
		self::log("Ein Client hat sich vom Server getrennt. Verbundene Clients: ".self::$iClientCount);
    }

    public function onSubscribe(Conn $oConn, $oTopic) 
    {
    	$sStatus = "Ein Client hat sich am Topic '".$oTopic->getId()."' angemeldet.";
    	self::log($sStatus);
    	$oTopic->broadcast(array('data' => $sStatus));
    }

    public function onUnSubscribe(Conn $oConn, $oTopic) 
    {
    	$sStatus = "Ein Client hat sich vom Topic '".$oTopic->getId()."' abgemeldet.";
		self::log($sStatus);
    	$oTopic->broadcast(array('data' => $sStatus));
    }

    public function onError(Conn $oConn, \Exception $e) 
    {
    	self::log("Ein Fehler ist aufgetreten!");
    }
	
	public static function log($sText)
	{
		echo date('H:i:s').": ".$sText."\n";
	}
}