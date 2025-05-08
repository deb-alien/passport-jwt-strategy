import { connect } from 'mongoose';
import { MONGO_URI } from './app.config.js';

const connectMongoDB = async () => {
	return (await connect(MONGO_URI)) ? true : false;
};

export default connectMongoDB;
