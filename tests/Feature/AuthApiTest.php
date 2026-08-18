<?php

use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Password;

uses(RefreshDatabase::class);

test('login requires email and password', function () {
    $response = $this->postJson('/api/login');

    $response->assertStatus(422)
             ->assertJsonValidationErrors(['email', 'password']);
});

test('login fails with invalid credentials', function () {
    $user = User::factory()->create([
        'email' => 'user@example.com',
        'password' => bcrypt('password123'),
    ]);

    $response = $this->postJson('/api/login', [
        'email' => 'user@example.com',
        'password' => 'wrongpassword',
    ]);

    $response->assertStatus(401)
             ->assertJson([
                 'message' => 'Invalid login credentials.'
             ]);
});

test('login succeeds with valid credentials and returns token', function () {
    $user = User::factory()->create([
        'email' => 'user@example.com',
        'password' => bcrypt('password123'),
    ]);

    $response = $this->postJson('/api/login', [
        'email' => 'user@example.com',
        'password' => 'password123',
    ]);

    $response->assertStatus(200)
             ->assertJsonStructure([
                 'message',
                 'access_token',
                 'token_type',
                 'user' => [
                     'id',
                     'name',
                     'email',
                 ]
             ]);
});

test('user cannot access profile without token', function () {
    $response = $this->getJson('/api/user');

    $response->assertStatus(401);
});

test('user can access profile with token', function () {
    $user = User::factory()->create();
    $token = $user->createToken('test_token')->plainTextToken;

    $response = $this->withHeader('Authorization', 'Bearer ' . $token)
                     ->getJson('/api/user');

    $response->assertStatus(200)
             ->assertJson([
                 'email' => $user->email,
             ]);
});

test('user can logout and invalidate token', function () {
    $user = User::factory()->create();
    $token = $user->createToken('test_token')->plainTextToken;

    $response = $this->withHeader('Authorization', 'Bearer ' . $token)
                     ->postJson('/api/logout');

    $response->assertStatus(200)
             ->assertJson([
                 'message' => 'Logged out successfully'
             ]);

    // Check that token is deleted
    expect($user->tokens()->count())->toBe(0);
});

test('registration validates inputs', function () {
    $response = $this->postJson('/api/register', []);

    $response->assertStatus(422)
             ->assertJsonValidationErrors(['name', 'email', 'password']);
});

test('registration succeeds with valid data', function () {
    $response = $this->postJson('/api/register', [
        'name' => 'New User',
        'email' => 'newuser@example.com',
        'password' => 'password123',
        'password_confirmation' => 'password123',
    ]);

    $response->assertStatus(201)
             ->assertJsonStructure([
                 'message',
                 'access_token',
                 'token_type',
                 'user' => [
                     'id',
                     'name',
                     'email',
                 ]
             ]);

    $this->assertDatabaseHas('users', [
        'email' => 'newuser@example.com',
    ]);
});

test('forgot password requires email', function () {
    $response = $this->postJson('/api/forgot-password', []);

    $response->assertStatus(422)
             ->assertJsonValidationErrors(['email']);
});

test('forgot password fails for non-existent email', function () {
    $response = $this->postJson('/api/forgot-password', [
        'email' => 'nonexistent@example.com'
    ]);

    $response->assertStatus(400);
});

test('forgot password sends reset link for valid email', function () {
    $user = User::factory()->create([
        'email' => 'testuser@example.com'
    ]);

    $response = $this->postJson('/api/forgot-password', [
        'email' => 'testuser@example.com'
    ]);

    $response->assertStatus(200)
             ->assertJson([
                 'message' => 'Password reset link sent to your email.'
             ]);
});

test('reset password resets the password using token', function () {
    $user = User::factory()->create([
        'email' => 'testuser@example.com'
    ]);

    // Generate token using Password Broker
    $token = Password::broker()->createToken($user);

    $response = $this->postJson('/api/reset-password', [
        'token' => $token,
        'email' => 'testuser@example.com',
        'password' => 'newpassword123',
        'password_confirmation' => 'newpassword123',
    ]);

    $response->assertStatus(200)
             ->assertJson([
                 'message' => 'Password has been reset successfully.'
             ]);

    // Check that we can login with the new password
    $loginResponse = $this->postJson('/api/login', [
        'email' => 'testuser@example.com',
        'password' => 'newpassword123',
    ]);

    $loginResponse->assertStatus(200);
});
