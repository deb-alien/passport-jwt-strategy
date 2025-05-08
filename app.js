import express from 'express';
import { createServer } from 'node:http';
import cookieParser from 'cookie-parser';

import { COOKIE_SECRET, HOST, PORT } from './config/app.config.js';
import connectMongoDB from './config/connectDB.js';

import authRoutes from './routes/auth.routes.js';

import './config/passport.config.js'

const app = express();
const server = createServer(app);

app.use(cookieParser(COOKIE_SECRET));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use('/api/v1/auth', authRoutes);

server.listen(PORT, HOST, async () => {
	try {
		(await connectMongoDB())
			? console.log('[Database connected]', `[Server is running on http://${HOST}:${PORT}]`)
			: process.exit(1);
	} catch (error) {
		throw error;
	}
});
