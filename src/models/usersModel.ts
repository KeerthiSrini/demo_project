import { Schema, model } from 'mongoose';

const userSchema = new Schema({
    firstName: { type: String, required: true },
    lastName: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    mobileNumber: { type: Number, required: true },
    role: { type: String, required: true, enum: ["USER", "ADMIN", "GUEST"]}
}, {
    timestamps: true,
});

export const User = model('User', userSchema);
