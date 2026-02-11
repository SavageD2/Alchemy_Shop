import { Entity } from 'typeorm';



@Entity()
export class User {
    private id: number;
    private email: string;
    private password: string;
    private role: 'admin' | 'alchimist';
}
