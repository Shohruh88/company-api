<?php
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use App\Models\User;

class AuthController extends Controller
{
public function register(Request $request)
{
$request->validate([
'name' => 'required',
'email' => 'required|email|unique:users',
'password' => 'required|confirmed',
'role' => 'required|in:admin,company'
]);

$user = User::create([
'name' => $request->name,
'email' => $request->email,
'password' => bcrypt($request->password),
'role' => $request->role,
]);

return response()->json([
'token' => $user->createToken("api-token")->plainTextToken,
'user' => $user
]);
}

public function login(Request $request)
{
$user = User::where('email', $request->email)->first();

if (!$user || !Hash::check($request->password, $user->password)) {
return response()->json(['message' => 'Invalid credentials'], 401);
}

return response()->json([
'token' => $user->createToken("api-token")->plainTextToken,
'user' => $user
]);
}
}
