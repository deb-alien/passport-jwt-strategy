import passport from 'passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import User from '../model/user.model.js';
import { ACCESS_TOKEN_SECRET, REFRESH_TOKEN_SECRET } from './app.config.js';

// ===== Access Token Strategy =====
passport.use(
	'jwt-access',
	new Strategy(
		{
			jwtFromRequest: ExtractJwt.fromExtractors([(req) => req?.signedCookies?.['access_token'] || null]),
			secretOrKey: ACCESS_TOKEN_SECRET,
			ignoreExpiration: false,
			audience: 'frontend',
			issuer: 'http://127.0.0.1:1337',
			algorithms: ['HS256'],
		},
		async (payload, done) => {
			try {
				const user = await User.findById(payload.sub);
				if (!user) return done(null, false);

				return done(null, user);
			} catch (error) {
				return done(error, false);
			}
		}
	)
);
// ===== Refresh Token Strategy =====
passport.use(
	'refresh-jwt',
	new Strategy(
		{
			jwtFromRequest: ExtractJwt.fromExtractors([(req) => req?.signedCookies?.['refresh_token'] || null]),
			secretOrKey: REFRESH_TOKEN_SECRET,
			ignoreExpiration: false,
			audience: 'frontend',
			issuer: 'http://127.0.0.1:1337',
			algorithms: ['HS256'],
		},

		async (payload, done) => {
			try {
				const user = await User.findById(payload.sub);
				if (!user || !user.refreshToken) return done(null, false);

				return done(null, user);
			} catch (error) {
				return done(error, false);
			}
		}
	)
);
