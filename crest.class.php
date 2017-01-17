<?php

class CREST {
    // https://api-sisi.testeveonline.com/
    // https://sisilogin.testeveonline.com
    private static $baseUrl = 'https://crest-tq.eveonline.com';
    private static $loginUrl = 'https://login.eveonline.com/oauth';

    public $lastError = null;
    public $characterID = null;
    public $accessToken = null;
    public $refreshToken = null;
    public $tokenExpire = null;

    public function login($scope = NULL, $state = 'evessologin') {
        global $crestClient;
        global $crestUrl;

        $params = array(
            'response_type' => 'code',
            'redirect_uri' => $crestUrl,
            'client_id' => $crestClient,
            'scope' => $scope,
            'state' => $state
        );

        header('Location: '. self::$loginUrl . '/authorize?' . http_build_query($params), true, 302);
    }

    public function authenticate($code) {
        global $crestSecret;
        global $crestClient;

        $header = 'Authorization: Basic '.base64_encode($crestClient.':'.$crestSecret);
        $params = array(
            'grant_type' => 'authorization_code',
            'code' => $code
        );

        $curl = curl_init();
		curl_setopt($curl, CURLOPT_URL, self::$loginUrl . '/token');
		curl_setopt($curl, CURLOPT_POST, true);
        curl_setopt($curl, CURLOPT_HTTPHEADER, array($header));
		curl_setopt($curl, CURLOPT_POSTFIELDS, http_build_query($params));
		curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
		// curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
		curl_setopt($curl, CURLOPT_USERAGENT, 'Tripwire 0.6.x daimian.mercer@gmail.com');

		$result = curl_exec($curl);

        if ($result === false) {
            $this->lastError = curl_error($curl);
            return false;
        }

        $response = json_decode($result);
        $this->accessToken = $response->access_token;
        $this->tokenExpire = date('Y-m-d H:i:s', time() + $response->expires_in);
        $this->refreshToken = $response->refresh_token;

        $header = 'Authorization: Bearer '. $this->accessToken;

        $curl = curl_init();
        curl_setopt($curl, CURLOPT_URL, self::$loginUrl . '/verify');
        curl_setopt($curl, CURLOPT_HTTPHEADER, array($header));
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        // curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($curl, CURLOPT_USERAGENT, 'Tripwire 0.6.x daimian.mercer@gmail.com');

        $result = curl_exec($curl);

        if ($result === false) {
            $this->lastError = curl_error($curl);
            return false;
        }

        $response = json_decode($result);
        if (!isset($response->CharacterID)) {
            $this->lastError = 'No character ID returned';
            return false;
        }

        return $this->characterID = $response->CharacterID;
    }

    public function refresh($refreshToken) {
        global $crestSecret;
        global $crestClient;

        $header = 'Authorization: Basic '.base64_encode($crestClient.':'.$crestSecret);
        $params = array(
            'grant_type' => 'refresh_token',
            'refresh_token' => $refreshToken
        );

        $curl = curl_init();
		curl_setopt($curl, CURLOPT_URL, self::$loginUrl . '/token');
		curl_setopt($curl, CURLOPT_POST, true);
        curl_setopt($curl, CURLOPT_HTTPHEADER, array($header));
		curl_setopt($curl, CURLOPT_POSTFIELDS, http_build_query($params));
		curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
		// curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
		curl_setopt($curl, CURLOPT_USERAGENT, 'Tripwire 0.6.x daimian.mercer@gmail.com');

		$result = curl_exec($curl);

        if ($result === false) {
            $this->lastError = curl_error($curl);
            return false;
        }

        $response = json_decode($result);

        if (!isset($response->access_token)) {
            return false;
        }

        $this->accessToken = $response->access_token;
        $this->tokenExpire = date('Y-m-d H:i:s', time() + $response->expires_in);
        $this->refreshToken = $response->refresh_token;

        return true;
    }

    public function characterLocation($accessToken, $characterID) {
        $header = 'Authorization: Bearer '. $accessToken;

        $curl = curl_init();
		curl_setopt($curl, CURLOPT_URL, self::$baseUrl . '/characters/'.$characterID.'/location/');
        curl_setopt($curl, CURLOPT_HTTPHEADER, array($header));
		curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
		// curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
		curl_setopt($curl, CURLOPT_USERAGENT, 'Tripwire 0.6.x daimian.mercer@gmail.com');

		$result = curl_exec($curl);

        if ($result === false) {
            $this->lastError = curl_error($curl);
            return false;
        }

        $response = json_decode($result);

        $location = new location();
        $location->systemID = isset($response->solarSystem) ? $response->solarSystem->id : null;
        $location->systemName = isset($response->solarSystem) ? $response->solarSystem->name : null;
        $location->stationID = isset($response->station) ? $response->station->id : null;
        $location->stationName = isset($response->station) ? $response->station->name : null;

        return $location;
    }

	public function characterInfo($characterID) {
		$curl = curl_init();
        curl_setopt($curl, CURLOPT_URL, self::$baseUrl . '/characters/'.$characterID.'/');
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_USERAGENT, 'Tripwire 0.6.x daimian.mercer@gmail.com');

        $result = curl_exec($curl);
            if ($result === false) {
                $this->lastError = curl_error($curl);
                return false;
            }
            $response = json_decode($result);
        $charName = isset($response->name) ? $response->name : null;
            return $charName;
        }
}

class location {
    public $systemID = null;
    public $systemName = null;
    public $stationID = null;
    public $stationName = null;
}

?>
