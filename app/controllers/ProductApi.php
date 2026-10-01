<?php
defined('PREVENT_DIRECT_ACCESS') OR exit('No direct script access allowed');

class ProductApi extends Controller
{
    private $api;
    private $db;

    public function __construct()
    {
        parent::__construct();
        $this->api = $this->call->library('api');
        $this->db = $this->call->database();
    }

    public function status()
    {
        $this->api->require_method('GET');
        $this->api->respond([
            'status' => 'ok',
            'service' => 'LavaLust API',
        ]);
    }

    public function login()
    {
        $this->api->require_method('POST');
        $input = $this->api->body();
        $identity = strtolower(trim((string) ($input['identity'] ?? '')));
        $password = (string) ($input['password'] ?? '');

        $this->ensure_demo_account($identity, $password);

        $user = $this->db->raw(
            'SELECT id, username, email, password, role, is_active FROM users WHERE email = ? OR username = ? LIMIT 1',
            [$identity, $identity]
        )->fetch(PDO::FETCH_ASSOC);

        if (!$user || !(int) $user['is_active'] || !password_verify($password, $user['password'])) {
            $this->api->respond_error('The email/username or password is incorrect.', 401);
        }

        $this->send_auth_response($user['id'], $user['username'], $user['email'], $user['role']);
    }

    public function register()
    {
        $this->api->require_method('POST');
        $input = $this->api->body();
        $username = trim((string) ($input['username'] ?? ''));
        $email = strtolower(trim((string) ($input['email'] ?? '')));
        $password = (string) ($input['password'] ?? '');
        $passwordConfirmation = (string) ($input['password_confirmation'] ?? '');

        if ($username === '' || strlen($username) > 100 || !filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($password) < 8 || !hash_equals($password, $passwordConfirmation)) {
            $this->api->respond_error('Enter a username, valid email, matching passwords, and a password with at least 8 characters.', 422);
        }

        $exists = $this->db->raw(
            'SELECT id FROM users WHERE username = ? OR email = ? LIMIT 1',
            [$username, $email]
        )->fetch(PDO::FETCH_ASSOC);
        if ($exists) {
            $this->api->respond_error('An account with that username or email already exists.', 409);
        }

        $this->db->raw(
            'INSERT INTO users (username, email, password, role, is_active) VALUES (?, ?, ?, ?, 1)',
            [$username, $email, password_hash($password, PASSWORD_DEFAULT), 'user']
        );

        $this->api->respond(['message' => 'Account created. Please sign in to continue.'], 201);
    }

    public function refresh()
    {
        $this->api->require_method('POST');
        $input = $this->api->body();
        $this->api->refresh_access_token((string) ($input['refresh_token'] ?? ''));
    }

    public function logout()
    {
        $this->api->require_method('POST');
        $input = $this->api->body();
        $refreshToken = (string) ($input['refresh_token'] ?? '');
        if ($refreshToken !== '') {
            $this->api->revoke_refresh_token($refreshToken);
        }

        $this->api->respond(['message' => 'Signed out.']);
    }

    public function products()
    {
        $this->api->require_method('GET');
        $this->api->require_jwt();
        $products = $this->db->raw(
            'SELECT id, product_name, description, price, quantity, created_at FROM products ORDER BY created_at DESC, id DESC'
        )->fetchAll(PDO::FETCH_ASSOC);

        foreach ($products as &$product) {
            $product['id'] = (int) $product['id'];
            $product['price'] = (float) $product['price'];
            $product['quantity'] = (int) $product['quantity'];
            $product['product_name'] = htmlspecialchars_decode($product['product_name'], ENT_QUOTES);
            $product['description'] = htmlspecialchars_decode((string) $product['description'], ENT_QUOTES);
        }
        unset($product);

        $this->api->respond(['data' => $products]);
    }

    public function create_product()
    {
        $this->api->require_method('POST');
        $this->require_admin();
        $product = $this->validated_product($this->api->body());

        $this->db->raw(
            'INSERT INTO products (product_name, description, price, quantity) VALUES (?, ?, ?, ?)',
            [$product['product_name'], $product['description'], $product['price'], $product['quantity']]
        );

        $this->api->respond(['data' => $this->find_product($this->db->last_id())], 201);
    }

    public function update_product($id)
    {
        $this->require_admin();
        $productId = (int) $id;
        if (!$this->find_product($productId)) {
            $this->api->respond_error('Product not found.', 404);
        }

        $product = $this->validated_product($this->api->body());
        $this->db->raw(
            'UPDATE products SET product_name = ?, description = ?, price = ?, quantity = ? WHERE id = ?',
            [$product['product_name'], $product['description'], $product['price'], $product['quantity'], $productId]
        );

        $this->api->respond(['data' => $this->find_product($productId)]);
    }

    public function delete_product($id)
    {
        $this->api->require_method('DELETE');
        $this->require_admin();
        $productId = (int) $id;
        if (!$this->find_product($productId)) {
            $this->api->respond_error('Product not found.', 404);
        }

        $this->db->raw('DELETE FROM products WHERE id = ?', [$productId]);
        $this->api->respond(['message' => 'Product deleted.']);
    }

    private function require_admin()
    {
        $auth = $this->api->require_jwt();
        if (($auth['role'] ?? 'user') !== 'admin') {
            $this->api->respond_error('Only administrators can modify products.', 403);
        }
    }

    private function ensure_demo_account($identity, $password)
    {
        $accounts = [
            'admin' => [
                'email' => 'admin@stockroom.local',
                'password' => 'Stockroom#2026',
                'role' => 'admin',
            ],
            'viewer' => [
                'email' => 'viewer@stockroom.local',
                'password' => 'Viewer#2026',
                'role' => 'user',
            ],
        ];
        $account = $accounts[$identity] ?? null;

        if (!$account || !hash_equals($account['password'], $password)) {
            return;
        }

        $exists = $this->db->raw(
            'SELECT id FROM users WHERE username = ? OR email = ? LIMIT 1',
            [$identity, $account['email']]
        )->fetch(PDO::FETCH_ASSOC);

        if ($exists) {
            return;
        }

        $this->db->raw(
            'INSERT INTO users (username, email, password, role, is_active) VALUES (?, ?, ?, ?, 1)',
            [$identity, $account['email'], password_hash($account['password'], PASSWORD_DEFAULT), $account['role']]
        );
    }

    private function send_auth_response($id, $username, $email, $role, $status = 200)
    {
        $roleScopes = [
            'admin' => ['read', 'write', 'delete'],
            'moderator' => ['read'],
            'user' => ['read'],
        ];
        $tokens = $this->api->issue_tokens([
            'id' => $id,
            'role' => $role,
            'scopes' => $roleScopes[$role] ?? ['read'],
        ]);
        $this->api->respond([
            'user' => ['id' => (int) $id, 'username' => $username, 'email' => $email, 'role' => $role],
            'tokens' => $tokens,
        ], $status);
    }

    private function validated_product($input)
    {
        $name = htmlspecialchars_decode(trim((string) ($input['product_name'] ?? '')), ENT_QUOTES);
        $description = htmlspecialchars_decode(trim((string) ($input['description'] ?? '')), ENT_QUOTES);
        $price = $input['price'] ?? null;
        $quantity = $input['quantity'] ?? null;

        if ($name === '' || strlen($name) > 100 || !is_numeric($price) || (float) $price < 0 || (float) $price > 99999999.99 || filter_var($quantity, FILTER_VALIDATE_INT) === false || (int) $quantity < 0) {
            $this->api->respond_error('Provide a product name (up to 100 characters), a valid non-negative price, and a non-negative whole-number quantity.', 422);
        }

        return [
            'product_name' => $name,
            'description' => $description,
            'price' => number_format((float) $price, 2, '.', ''),
            'quantity' => (int) $quantity,
        ];
    }

    private function find_product($id)
    {
        $product = $this->db->raw(
            'SELECT id, product_name, description, price, quantity, created_at FROM products WHERE id = ? LIMIT 1',
            [$id]
        )->fetch(PDO::FETCH_ASSOC);

        if (!$product) {
            return null;
        }

        $product['id'] = (int) $product['id'];
        $product['price'] = (float) $product['price'];
        $product['quantity'] = (int) $product['quantity'];
        $product['product_name'] = htmlspecialchars_decode($product['product_name'], ENT_QUOTES);
        $product['description'] = htmlspecialchars_decode((string) $product['description'], ENT_QUOTES);

        return $product;
    }
}