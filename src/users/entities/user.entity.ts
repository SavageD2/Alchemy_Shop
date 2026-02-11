import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm';



@Entity()
export class User {
    @PrimaryGeneratedColumn()
    private id: number;
    @Column()
    email: string;
    @Column({ select: false })
    password: string;
    @Column()
    private role: 'admin' | 'alchimist';
}
