import {
	ACCESS_TOKEN_EXPIRES_IN,
	ACCESS_TOKEN_SECRET,
	NODE_ENV,
	REFRESH_TOKEN_EXPIRES_IN,
	REFRESH_TOKEN_SECRET,
} from '../config/app.config.js';
import { compareHash, createHash, issueCookie, issueToken, verifyToken } from '../lib/utils.js';
import User from '../model/user.model.js';

//* === Sing Up Contoller POST /api/v1/auth/signup ===
export const signup = async (req, res) => {
	try {
		const { email, password } = req.body;
		if (!email || !password) return res.status(400).json('All fields are required');

		if (await User.findOne({ email })) return res.status(403).json('Credentials Taken');

		const pwdHash = await createHash(password, 10);
		await User.create({
			email,
			password: pwdHash,
		});

		return res.status(201).json('Sign Up Successfull -- Please visit http://127.0.0.1:1337/api/v1/auth/login');
	} catch (error) {
		return res.status(500).json({
			error: 'Internal Server Error',
			error_name: error.name,
			error_msg: error.message,
			err_stack: error.stack,
		});
	}
};

//* === Login Contoller POST /api/v1/auth/loign ===
export const login = async (req, res) => {
	try {
		const { email, password } = req.body;
		if (!email || !password) return res.status(400).json('All fields are requied.');

		const user = await User.findOne({ email });
		if (!user) return res.status(403).json('Invalid Credentials');

		const pwdMatch = await compareHash(password, user.password);
		if (!pwdMatch) return res.status(403).json('Invalid Credentials');

		const accessToken = issueToken({ sub: user._id, email: user.email }, ACCESS_TOKEN_SECRET, {
			algorithm: 'HS256',
			audience: 'frontend',
			issuer: 'http://127.0.0.1:1337',
			expiresIn: ACCESS_TOKEN_EXPIRES_IN,
		});
		const refreshToken = issueToken({ sub: user._id, email: user.email }, REFRESH_TOKEN_SECRET, {
			algorithm: 'HS256',
			audience: 'frontend',
			issuer: 'http://127.0.0.1:1337',
			expiresIn: REFRESH_TOKEN_EXPIRES_IN,
		});

		user.refreshToken = await createHash(refreshToken, 10);
		await user.save();

		issueCookie(res, 'access_token', accessToken, {
			httpOnly: true,
			signed: true,
			secure: NODE_ENV === 'production',
			maxAge: 15 * 60 * 1000,
			sameSite: 'lax',
		});
		issueCookie(res, 'refresh_token', refreshToken, {
			httpOnly: true,
			signed: true,
			secure: NODE_ENV === 'production',
			maxAge: 7 * 24 * 60 * 60 * 1000,
			sameSite: 'lax',
		});

		return res.status(200).json('Login Successfull.');
	} catch (error) {
		console.log(error);
		return res.status(500).json({
			error: 'Internal Server Error',
			error_name: error.name,
			error_msg: error.message,
			err_stack: error.stack,
		});
	}
};

//* === RefreshToken Contoller POST /api/v1/auth/refresh ===
export const refresh = async (req, res) => {
	try {
		const user = req.user;
		const rawToken = req.signedCookies['refresh_token'];

		const isTokenValid = await compareHash(rawToken, user.refreshToken);
		if (!isTokenValid) return res.status(401).json('Invalid Refresh Token');

		const accessToken = issueToken({ sub: user._id, email: user.email }, ACCESS_TOKEN_SECRET, {
			algorithm: 'HS256',
			audience: 'frontend',
			issuer: 'http://127.0.0.1:1337',
			expiresIn: ACCESS_TOKEN_EXPIRES_IN,
		});
		const refreshToken = issueToken({ sub: user._id, email: user.email }, REFRESH_TOKEN_SECRET, {
			algorithm: 'HS256',
			audience: 'frontend',
			issuer: 'http://127.0.0.1:1337',
			expiresIn: REFRESH_TOKEN_EXPIRES_IN,
		});

		user.refreshToken = await createHash(refreshToken, 10);
		await user.save();

		issueCookie(res, 'access_token', accessToken, {
			httpOnly: true,
			signed: true,
			secure: NODE_ENV === 'production',
			maxAge: 15 * 60 * 1000,
			sameSite: 'lax',
		});
		issueCookie(res, 'refresh_token', refreshToken, {
			httpOnly: true,
			signed: true,
			secure: NODE_ENV === 'production',
			maxAge: 7 * 24 * 60 * 60 * 1000,
			sameSite: 'lax',
		});

		return res.status(200).json('Token Refreshed');
	} catch (error) {
		return res.status(500).json({
			error: 'Internal Server Error',
			error_name: error.name,
			error_msg: error.message,
			err_stack: error.stack,
		});
	}
};

//* === Logout Contoller POST /api/v1/auth/logour ===
export const logout = async (req, res) => {
	try {
		const rawToken = req.signedCookies.refresh_token;
		if (!rawToken) {
			res.status(204).clearCookie('access_token', { maxAge: 0 });
			res.clearCookie('refresh_token', { maxAge: 0 });
			return res.sendStatus(204);
		}

		const decoded = verifyToken(rawToken, REFRESH_TOKEN_SECRET);

		const user = await User.findById(decoded.sub);
		if (!user) {
			res.clearCookie('access_token', { maxAge: 0 });
			res.clearCookie('refresh_token', { maxAge: 0 });
			return res.status(401).json('Invalid or Expired Token');
		}
		user.refreshToken = null;
		await user.save();

		return res
			.clearCookie('access_token', { maxAge: 0 })
			.clearCookie('refresh_token', { maxAge: 0 })
			.status(200)
			.json('User Logged Out');
	} catch (error) {
		return res.status(500).json({
			error: 'Internal Server Error',
			error_name: error.name,
			error_msg: error.message,
			err_stack: error.stack,
		});
	}
};
