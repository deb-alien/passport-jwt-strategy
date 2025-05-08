import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

export const compareHash = async (data, hash) => {
	return await bcrypt.compare(data, hash);
};

export const createHash = async (data, salt) => {
	const saltRound = await bcrypt.genSalt(salt);
	return await bcrypt.hash(data, saltRound);
};

export const issueToken = (payload, secret, options) => {
	return jwt.sign(payload, secret, options);
};

export const verifyToken = (token, secret) => {
    return jwt.verify(token, secret)
}

export const issueCookie = (res, name, val, options) => {
	res.cookie(name, val, options);
};
