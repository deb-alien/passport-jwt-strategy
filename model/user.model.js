import mongoose from 'mongoose';

const { Schema, models, model } = mongoose;

const UserSchema = new Schema(
	{
		email: {
			type: String,
			required: true,
			unique: true,
			lowercase: true,
			trim: true,
		},
		password: {
			type: String,
			required: true,
		},
		refreshToken: {
			type: String,
			default: null,
		},
	},
	{ timestamps: true }
);
const User = models.User || model('user', UserSchema);

export default User;
