<?php
defined('PREVENT_DIRECT_ACCESS') OR exit('No direct script access allowed');
/**
 * ------------------------------------------------------------------
 * LavaLust - an opensource lightweight PHP MVC Framework
 * ------------------------------------------------------------------
 *
 * MIT License
 *
 * Copyright (c) 2020 Ronald M. Marasigan
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * @package LavaLust
 * @author Ronald M. Marasigan <ronald.marasigan@yahoo.com>
 * @since Version 4
 * @link https://github.com/ronmarasigan/LavaLust
 * @license https://opensource.org/licenses/MIT MIT License
 */

/*
|--------------------------------------------------------------------------
| Enable/Disable Migrations
|--------------------------------------------------------------------------
|
| Migrations are disabled by default for security reasons.
| You should enable migrations whenever you intend to do a schema migration
| and disable it back when you're done.
|
*/
$config['api_helper_enabled'] = TRUE;

/*
|--------------------------------------------------------------------------
| Payload Token Expiration
|--------------------------------------------------------------------------
|
| Used for Payload Token Expiration
|
*/
$config['payload_token_expiration'] = 900;


/*
|--------------------------------------------------------------------------
| Refresh Token Expiration
|--------------------------------------------------------------------------
|
| Used for Refresh Token Expiration
|
*/
$config['refresh_token_expiration'] = 604800;

/*
|--------------------------------------------------------------------------
| JWT Secret Token
|--------------------------------------------------------------------------
|
| Used for Securing endpoint
|
*/
$app_key = getenv('APP_KEY') ?: '';
$derived_jwt_secret = strlen($app_key) >= 32
	? hash_hmac('sha256', 'lavalust-api-jwt', $app_key)
	: '';
$derived_refresh_key = strlen($app_key) >= 32
	? hash_hmac('sha256', 'lavalust-api-refresh', $app_key)
	: '';

$config['jwt_secret'] = getenv('API_JWT_SECRET') ?: $derived_jwt_secret;

/*
|--------------------------------------------------------------------------
| Refresh Token
|--------------------------------------------------------------------------
|
| Used for Securing endpoint
|
*/
$config['refresh_token_key'] = getenv('API_REFRESH_TOKEN_KEY') ?: $derived_refresh_key;

/*
|--------------------------------------------------------------------------
| Access-Control-Allow-Origin
|--------------------------------------------------------------------------
|
| Access-Control-Allow-Origin - change this to your domain if
| already deployed.
|
*/
$frontend_origins = array_values(array_filter(array_map(
	'trim',
	explode(',', getenv('FRONTEND_ORIGIN') ?: '*')
)));

if (count($frontend_origins) === 1) {
	$origin_host = parse_url($frontend_origins[0], PHP_URL_HOST);
	if ($origin_host === 'localhost') {
		$frontend_origins[] = preg_replace('#://localhost(?=[:/]|$)#', '://127.0.0.1', $frontend_origins[0]);
	} elseif ($origin_host === '127.0.0.1') {
		$frontend_origins[] = preg_replace('#://127\.0\.0\.1(?=[:/]|$)#', '://localhost', $frontend_origins[0]);
	}
}

$config['allow_origin'] = count($frontend_origins) === 1
	? $frontend_origins[0]
	: $frontend_origins;

/*
|--------------------------------------------------------------------------
| Refresh Token Table
|--------------------------------------------------------------------------
|
| This is the name of the table that will store the Refresh Token.
|
*/
$config['refresh_token_table'] = 'refresh_tokens';

/*
|--------------------------------------------------------------------------
| JWT Issuer and Audience
|--------------------------------------------------------------------------
| These are used for JWT Issuer and Audience claims.
|
*/
$config['jwt_issuer'] = 'your-app';

/*
|--------------------------------------------------------------------------
| JWT Issuer and Audience
|--------------------------------------------------------------------------
| These are used for JWT Issuer and Audience claims.
|
*/

$config['jwt_audience'] = 'your-app-clients';

/*
|--------------------------------------------------------------------------
| Rate Limiting
|--------------------------------------------------------------------------
| These settings are used for API rate limiting.
|
*/
$config['rate_limit_enabled'] = true;

/*
|--------------------------------------------------------------------------
| Rate Limiting Requests and Seconds
|--------------------------------------------------------------------------
| These settings define the number of requests allowed and the time 
| window in seconds.
|
*/
$config['rate_limit_requests'] = 60;

/*
|--------------------------------------------------------------------------
| Rate Limiting Seconds
|--------------------------------------------------------------------------
| This setting defines the time window in seconds for rate limiting.
|
*/
$config['rate_limit_seconds'] = 60;