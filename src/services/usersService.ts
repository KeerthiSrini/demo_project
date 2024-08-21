import bcrypt from "bcrypt";
import { encrypt } from "./common";

export async function passwordEncrypt(myPlaintextPassword:string) {
    const pass = await bcrypt.hash(myPlaintextPassword, 10).then((hash) => {
        return (hash);
    });
    return pass;
}

export async function passwordMatchCheck(myPlaintextPassword:any, hash: any) {
    const result = await bcrypt.compare(myPlaintextPassword, hash).then((res) => {
        return (res);
    });
    return result;
}

export async function generateLoginResponse(user:any) {
    const TOKEN_EXPIRATION = 300_000;
    const expiry = Date.now() + TOKEN_EXPIRATION;

    const userData = {
        id: user._id.toString(),
        email: user.email,
        role: user.role,
        expiry,
    };
    const accessToken = encrypt(JSON.stringify(userData));

    const tokenData = {
        access_token: accessToken,
        expiry,
        iat: Date.now(),
    };

    return encrypt(JSON.stringify(tokenData));
}