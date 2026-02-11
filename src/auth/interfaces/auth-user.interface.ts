export interface AuthenticatedUser {
    id: number;
    email: string;
    role: 'admin' | 'alchimist';
}