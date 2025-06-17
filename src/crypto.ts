import { createHash, randomUUID } from 'crypto';

export function sha256(data: string | Buffer): string {
    return createHash('sha256').update(data).digest('hex');
}

export function createToken() {
    //random uuid returned in the form of a string
    return randomUUID();
}