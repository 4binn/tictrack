<?php

use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;

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
