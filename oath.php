<?php
 /***********************************************************************
     * OATH-PHP
     * Sample PHP code implementing OATH RFC 4226 - RFC 6238 - RFC 6287
	 * Made by IRETH S.R.L. (http://www.ireth.net/)
     * 
	 * This sample code has no warranty, it is provided “as is”. 
	 * It is your responsibility to validate the behavior of the routines 
	 * and their accuracy.
	 *
	 * The authors take no responsability for any consequences that may 
	 * arise from using this code.
	 * 
     * @package oath    
     * @author Walter Summonte
     * @version 1.0
     * @access public
	 * 
	 * Please send any contributions at support@ireth.net
*************************************************************************/
include('hex2bin.php');

$phpminversion = '5.1.02'; // hmac_result() minimal requirement 
if (version_compare(phpversion(), $phpminversion, '<')) {
    throw new Exception('PHP Version too much old');
}
 
function hotp($secret, $counter)	// $secret[binary], $counter[binary]
{
	$algo = 'sha1';
	if (strlen($counter)!= 8) throw new Exception(sprintf('Wrong counter size'));
	$hmac_result = hash_hmac ( $algo ,$counter ,$secret ,true);
	$last = strlen($hmac_result) - 1;
	$offset = ord($hmac_result[$last]) & 0xf;
	$bin_code = (ord($hmac_result[$offset])  & 0x7f) << 24
           | (ord($hmac_result[$offset+1]) & 0xff) << 16
           | (ord($hmac_result[$offset+2]) & 0xff) <<  8
           | (ord($hmac_result[$offset+3]) & 0xff) ;
	return $bin_code;
}

function totp($secret, $timestep, $algo='sha1' ,$t = null) // $secret[binary],$timestep[string/integer], $algo[string], $t[string/integer]
{
	if (!isset($t)) $t = time();
	$algo = strtolower($algo);
		if (!in_array($algo, array('sha1', 'sha256', 'sha512'), true)) {
				throw new \LogicException(sprintf('The hash algorithm "%s" is not supported.', $algo));
			}
	$counter=bcdiv($t , $timestep, 0); 
	$counter = base_convert($counter, 10, 16); 
	if (strlen($counter) > 16) throw new Exception(sprintf('Wrong timesteps size'));
	$counter=hex2bin(str_pad($counter,16,"0", STR_PAD_LEFT));

	$hmac_result = hash_hmac($algo ,$counter ,$secret ,true);
	$last = strlen($hmac_result) - 1;
	$offset = ord($hmac_result[$last]) & 0xf;
	$bin_code = (ord($hmac_result[$offset])  & 0x7f) << 24
           | (ord($hmac_result[$offset+1]) & 0xff) << 16
           | (ord($hmac_result[$offset+2]) & 0xff) <<  8
           | (ord($hmac_result[$offset+3]) & 0xff) ;
	return $bin_code;
}

class suite
{
	public $version;
	public $standard;
	public $algo;
	public $len;
	public $counter = false;
	public $qmode;
	public $qlen;
	public $palgo;
	public $session;
	public $tstep;
	
	private $OCRA_SUITES = array(
				// Authentication
                "OCRA-1:HOTP-SHA1-6:QA06",
                "OCRA-1:HOTP-SHA1-6:QA06-PSHA1",
                "OCRA-1:HOTP-SHA1-6:C-QA06",
                "OCRA-1:HOTP-SHA1-6:QA06-T30S",
                "OCRA-1:HOTP-SHA1-8:QN08",
                "OCRA-1:HOTP-SHA1-8:C-QN08",
                "OCRA-1:HOTP-SHA1-8:QN08-T30S",
                "OCRA-1:HOTP-SHA256-6:QA06-T30S",
                "OCRA-1:HOTP-SHA256-8:QA08",
                "OCRA-1:HOTP-SHA256-8:C-QA08",
                "OCRA-1:HOTP-SHA256-8:C-QA08-PSHA256",
                "OCRA-1:HOTP-SHA256-8:QA08-T30S",
                "OCRA-1:HOTP-SHA256-8:QA08-PSHA256-T30S",
                // Signature
                "OCRA-1:HOTP-SHA1-6:QH40",
                "OCRA-1:HOTP-SHA1-6:QA32",
                "OCRA-1:HOTP-SHA1-8:QH40",
                "OCRA-1:HOTP-SHA256-8:QA32",
                "OCRA-1:HOTP-SHA256-8:QH64",
                "OCRA-1:HOTP-SHA1-6:QA32-T30S",
                "OCRA-1:HOTP-SHA1-6:QH40-T30S",
                "OCRA-1:HOTP-SHA1-8:QA32-T30S",
                "OCRA-1:HOTP-SHA1-8:QH40-T30S",
                "OCRA-1:HOTP-SHA256-6:QH64-T30S",
                "OCRA-1:HOTP-SHA256-8:QA32-T30S",
                "OCRA-1:HOTP-SHA256-8:QH64-T30S");
		   
	function __construct($suite){
	   $suite = strtoupper($suite);
	   $this->standard = false;
	   foreach( $this->OCRA_SUITES as $testSuite)
					   if(strtoupper($suite) ==  $testSuite)
									   {$this->standard = true;}
	   $suite_data = explode ( ':' , $suite);
	   if (count($suite_data) != 3) throw new Exception('Unsupported OCRA-1 Suite');
	   $version = $suite_data[0];
	  
	   $hash_data = explode ( '-' , $suite_data[1]);
	   if (count($hash_data) != 3) throw new Exception('Unsupported OCRA-1 Suite');
	   $this->algo = $hash_data[1];
	   if (!in_array($this->algo, array('SHA1', 'SHA256', 'SHA512'), true)) throw new \LogicException(sprintf('The algorithm "%s" is not supported.', $algo));
	   $this->len = (int)$hash_data[2];
	   $maxlen = strlen(hash($this->algo,'len'));
	   if ($this->len == 0) $this->len = $maxlen;
	   if (($this->len < 4) || ($this->len > $maxlen)) throw new Exception('Unsupported OCRA-1 Suite output length');
	  
	   $question_data =  explode ( '-' , $suite_data[2]);
	   if (count($question_data) < 1) throw new Exception('Unsupported OCRA-1 Suite');
	   foreach($question_data as $questionValue){
		   switch (substr($questionValue,0,1)) {
			   case 'C':
						if (strlen($questionValue)!=1) throw new Exception('Unsupported OCRA-1 Suite');
						$this->counter=true;
						break;
			   case 'Q':	// N Numeric, A Alphanumeric, H Hash value
						if (strlen($questionValue)!=4) throw new Exception('Unsupported OCRA-1 Suite');
						$this->qmode=substr($questionValue,1,1);
						$this->qlen=(int)substr($questionValue,2,2);
						if (($this->qlen < 4) || ($this->qlen > 64)) throw new Exception('Unsupported OCRA-1 Suite');
						break;
			   case 'P':	// HASH PIN using SHA-1, SHA256, SHA512
						$this->palgo=str_replace('P','',$questionValue);
						if (!in_array($this->palgo, array('SHA1', 'SHA256', 'SHA512'), true)) throw new \LogicException(sprintf('The algorithm "%s" is not supported.', $algo));
						break;
			   case 'S':	//UTF-8 session value up to 512 bytes
						if (strlen($questionValue)!=4) throw new Exception('Unsupported OCRA-1 Suite');
						$this->session=(int)substr($questionValue,1,3);
						break;
			   case 'T':	// 8-byte unsigned integer in big-endian order
						if (strlen($questionValue) < 3) throw new Exception('Unsupported OCRA-1 Suite');
						$tval = (int)substr($questionValue,1,count($questionValue)-2);
						$mul = substr($questionValue,strlen($questionValue)-1,1);
						switch ($mul) {
								case 'S':	
										$mul=(int)1;
										break;
								case 'M':
										$mul=(int)60;
										break;
								case 'H':
										$mul=(int)3600;
										break;
								default:
										throw new Exception('Unsupported OCRA-1 Suite');
								}
						$this->tstep = $tval * $mul;
						break;
			   default:
						throw new Exception('Unsupported OCRA-1 Suite');
		   }
	   }
	}
}             
            
function ocra($secret, $suite, $question, $counter=null, $pinhash=null, $session=null, $t=null){ // $secret[binary],$suite[string],$question[string/binary],$counter[decimal], $pinhash[binary], $session[binary], $time[decimal]
	$mysuite = new suite($suite);
	switch ($mysuite->qmode){
		case 'N':	//Question value is a Number 4-64 len but 128 pad(2 question)
			$question = base_convert($question, 10, 16);
			$question = str_pad($question,128 *2 ,"0", STR_PAD_RIGHT);
			$question = hex2bin($question);
			break;
		case 'A':	//Question value is a AlphaNum Value
			$question = GenerateQS_NoHash($question,$mysuite->qlen);
			$question = str_pad($question,128,chr(0), STR_PAD_RIGHT);
			break;
		case 'H':	//Question is hash (binary) 
			if (strlen($question) != $mysuite->qlen) throw new \LogicException(sprintf('The question has wrong size.'));
			$question = ($question);
			break;
		default:
	}
	
	$data = $suite . chr(0);
	if(isset($counter) && $mysuite->counter ) {
		$counter = base_convert($counter, 10, 16);
		if (strlen($counter)> 16)  throw new \LogicException(sprintf('Counter too much big.'));
		$counter=hex2bin(str_pad($counter,16,"0", STR_PAD_LEFT));
		$data .= $counter;
	}
	$data .= $question;
	if (isset($mysuite->palgo)) {
		if((strlen($pinhash) != 20) && ($mysuite->palgo == 'SHA1')) throw new \LogicException(sprintf('The PIN HASH has wrong size.'));
		if((strlen($pinhash) != 32) && ($mysuite->palgo == 'SHA256')) throw new \LogicException(sprintf('The PIN HASH has wrong size.'));
		if((strlen($pinhash) != 64) && ($mysuite->palgo == 'SHA512')) throw new \LogicException(sprintf('The PIN HASH has wrong size.'));
		$data .= $pinhash;
	}
	if (isset($mysuite->session) && (strlen($session) != $mysuite->session)) throw new \LogicException(sprintf('The Session size/value is wrong.'));
	else $data .= $session;

	if (isset($mysuite->tstep)){
		if (!isset($t)) $t = time();
		$tcounter=bcdiv($t , $mysuite->tstep, 0); 
		$tcounter = base_convert($tcounter, 10, 16); 
		$tcounter=hex2bin(str_pad($tcounter,16,"0", STR_PAD_LEFT));
		$data .= $tcounter;
	}
	
	//echo "\n\r" . bin2hex($data);
	
	$hmac_result = hash_hmac ( $mysuite->algo ,$data ,$secret ,true);	
	$last = strlen($hmac_result) - 1;
	$offset = ord($hmac_result[$last]) & 0xf;
	$bin_code = (ord($hmac_result[$offset])  & 0x7f) << 24
           | (ord($hmac_result[$offset+1]) & 0xff) << 16
           | (ord($hmac_result[$offset+2]) & 0xff) <<  8
           | (ord($hmac_result[$offset+3]) & 0xff) ;
	return substr($bin_code, strlen($bin_code) - $mysuite->len, $mysuite->len);
}


function GenerateQS_NoHash($question, $len){
	return str_pad($question,$len,"~", STR_PAD_RIGHT);
}

function GenerateQS_SHA1($question){
	return hash('sha1',$question,true);
} // MUST be used to generate the QH40 Question

function GenerateQS_SHA256($question){
	return hash('sha256',$question,true);
} // MUST be used to generate the QH64 Question


?>

 
