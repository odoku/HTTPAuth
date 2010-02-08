<?php
/**
 * HTTPAuth.php
 * 
 * このファイルにはHTTPAuthクラスに関する定義が記述されています。<br/>
 * このファイルを読み込むことによりHTTPAuthクラスの使用が可能になります。
 */


/**
 * PHPでBasic認証、Digest認証機能を提供します。
 * 
 * @package    http_auth
 * @subpackage net
 * @author     odoku <odoku@shamoo.org>
 * @copyright  Copyright © 2009, shamoo.org
 * @license    shamoo.org License Ver. 1.0
 * @version    1.0
 * @access     public
 */
class HTTPAuth {
	/**
	 * Basic認証を行います。
	 *
	 * 第2引数には、IDを引数としパスワード文字列を戻り値とする関数へのコールバックを指定して下さい。
	 * このメソッドはレスポンスヘッダーを吐き出します。
	 * レスポンスボディが出力された後に実行した場合、Warningが出力される事に注意して下さい。
	 *
	 * <code>
	 * 
	 * function getPassword($account) {
	 *     if (strcmp('foo', $account) === 0) {
	 *         return 'bar';
	 *     }
	 *     return false;
	 * }
	 * 
	 * $realm = 'Please input your user name & password.';
	 * $callback = 'getPassword';
	 * 
	 * if (HTTPAuth::basic($realm, $callback)) {
	 *     echo 'ok.':
	 * } else {
	 *     echo 'failed.';
	 * }
	 * 
	 * </code>
	 * 
	 * @access     public
	 * @static
	 * @return     true 認証に成功した場合はtrueを、失敗した場合はfalseを返します。
	 * @param      string $realm realm文字列。
	 * @param      callback $callback パスワード取得関数へのコールバック 
	 */
	public static function basic($realm, $callback) {
		if (
			!array_key_exists('PHP_AUTH_USER', $_SERVER) ||
			!($password = call_user_func_array($callback, array($_SERVER['PHP_AUTH_USER']))) ||
			strcmp($_SERVER['PHP_AUTH_PW'], $password) !== 0
		) {
			header('http/1.1 401 Unauthorized');
			header(sprintf('WWW-Authenticate: Basic realm="%s"', $realm));
			return false;
		} else {
			return true;
		}
	}
	
	/**
	 * Digest認証を行います。
	 *
	 * 第2引数には、IDを引数としパスワード文字列を戻り値とする関数へのコールバックを指定して下さい。
	 * このメソッドはレスポンスヘッダーを吐き出します。
	 * レスポンスボディが出力された後に実行した場合、Warningが出力される事に注意して下さい。
	 *
	 * PHPがApacheのモジュールとして動作していない場合、このメソッドはは正常に動作しません。
	 *
	 * <code>
	 * 
	 * function getPassword($account) {
	 *     if (strcmp('hoge', $account) === 0) {
	 *         return 'password';
	 *     }
	 *     return false;
	 * }
	 * 
	 * $realm = 'Please input your user name & password.';
	 * $callback = 'getPassword';
	 * 
	 * if (HTTPAuth::digest($realm, $callback)) {
	 *     echo 'ok.':
	 * } else {
	 *     echo 'failed.';
	 * }
	 * 
	 * </code>
	 * 
	 * @access     public
	 * @static
	 * @return     true 認証に成功した場合はtrueを、失敗した場合はfalseを返します。
	 * @param      string $realm realm文字列。
	 * @param      callback $callback パスワード取得関数へのコールバック 
	 */
	public static function digest($realm, $callback) {
		$digest = self::__getDigest();
		
		if(
			$digest === false ||
			!($password = call_user_func_array($callback, array($digest['Digest username']))) ||
			strcmp($digest['response'], self::__generateDigestHash($digest, $realm, $password)) !== 0
		) {
			header('http/1.1 401 Unauthorized');
			header(sprintf(
				'WWW-Authenticate: Digest realm="%s",qop="auth",nonce="%s",opaque="%s",algorithm="MD5"',
				$realm, uniqid(rand(), true), md5($realm)
			));
			return false;
		} else {
			return true;
		}
	}
	
	/**
	 * ブラウザから送信されたDigest情報を取得します。
	 *
	 * PHPがApacheのモジュールとして動作していない場合、このメソッドはは正常に動作しません。
	 *
	 * @access     private
	 * @static
	 * @return     array 認証に成功した場合はDigest情報が保持された配列を、失敗した場合はfalseを返します。
	 */
	private static function __getDigest() {
		$headers = apache_request_headers();
		if (!array_key_exists('Authorization', $headers)) return false;
		
		preg_match_all('/([\w ]+)="?([^",]*)"?/', $headers['Authorization'], $matchies);
		$digest = array();
		for ($i = 0; $i < count($matchies[0]); $i++) {
			$digest[trim($matchies[1][$i])] = trim($matchies[2][$i]);
		}
		
		return $digest;
	}
	
	/**
	 * Digestハッシュを生成します。
	 *
	 * @access     private
	 * @static
	 * @return     array 認証に成功した場合はDigest情報が保持された配列を、失敗した場合はfalseを返します。
	 * @param      array $digest ブラウザから送信されたDigest情報を保持した配列。
	 * @param      string $realm realm文字列。
	 * @param      string $password パスワード文字列。
	 */
	private static function __generateDigestHash($digest, $realm, $password) {
		if (ini_get('safe_mode')) {
			$realm .= '-' . getmyuid();
		}
		
		$hash1 = md5(sprintf("%s:%s:%s", $digest['Digest username'], $realm, $password));
		$hash2 = md5(sprintf("%s:%s", $_SERVER['REQUEST_METHOD'], $digest['uri']));
		$hash3 = md5(sprintf(
			"%s:%s:%s:%s:%s:%s",
			$hash1,
			$digest['nonce' ],
			$digest['nc'    ],
			$digest['cnonce'],
			$digest['qop'   ],
			$hash2
		));
		
		return $hash3;
	}
}