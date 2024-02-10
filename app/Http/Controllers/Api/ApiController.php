<?php

namespace App\Http\Controllers\Api;

use App\Models\User;
use Illuminate\Support\Str;
use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use Illuminate\Auth\Events\Verified;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
// use Illuminate\Notifications\Messages\VonageMessage;

class ApiController extends Controller
{
    public function register(Request $request)
    {

        $request->validate([
            "name" => "required",
            "email" => "required|email|unique:users",
            "password" => "required|"
        ]);

         $user= User::create([
            "name" => $request->name,
            "email" => $request->email,
            "password" => Hash::make($request->password),
            "email_verification_code"=> Str::random(6)
        ]);
        // return response()->json([
        //     "status" => true,
        //     "message" => "User created successfully"
        // ]);
        $user->sendEmailVerificationNotification();
        return response()->json(['message' => 'Registration successful. Verification email sent.'], 200
    );

    }




    public function verifyCode(Request $request)
    {  $validator = Validator::make($request->all(), [
        "email" => "required|email",
        "verification_code" => "required"
    ]);

        $validator = User::where('email', $request->email)
                    ->where('email_verification_code', $request->email_verification_code)
                    ->first();

        if (!$validator) {
            return response()->json(['error' => 'Invalid verification code'], 400);
        }

        $validator->email_verified = true;
        $validator->save();

        return response()->json(['message' => 'Email verified successfully'], 200);
    }
    public function verify(Request $request)
    {
        $user = User::find($request->route('id'));
        if (!$user) {
            return response()->json(['error' => 'User not found'], 404);
        }

        if ($user->hasVerifiedEmail()) {
            return response()->json(['message' => 'User already verified'], 400);
        }
        $user->markEmailAsVerified();
        event(new Verified($user));

        return response()->json(['message' => 'Email verified'], 200,);
    }

    public function login(Request $request)
    {
        $request->validate([
            "email" => "required|email",
            "password" => "required"
        ]);
        if(Auth::attempt([
            "email" => $request->email,
            "password" => $request->password
        ])){
            $user = Auth::user();

            $token = $user->createToken("myToken")->accessToken;

            return response()->json([
                "status" => true,
                "message" => "Login successful",
                "access_token" => $token
            ]);
        }

        return response()->json([
            "status" => false,
            "message" => "Invalid credentials"
        ]);
    }

    public function Profil ()
    {
        $userdata = Auth::user();

        return response()->json([
            "status" => true,
            "message" => "Profile data",
            "data" => $userdata
        ]);
    }
    public function logout(Request $request)
    {

        auth()->user()->token()->revoke();

        return response()->json([
            "status" => true,
            "message" => "User logged out"
        ]);

    }

}
