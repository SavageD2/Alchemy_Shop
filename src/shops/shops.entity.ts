import { Entity, Column, PrimaryGeneratedColumn, OneToMany } from 'typeorm';
import { Potion } from 'src/potion/potion.entity';
import { User } from 'src/users/entities/user.entity';

@Entity()
export class Shop {
    @PrimaryGeneratedColumn('uuid')
    id: string;
    @Column()
    name: string;
    @Column()
    location: string;
    @OneToMany(() => Potion, (potion) => potion.shop)
    potions: Potion[];

    @OneToMany(() => User, (user) => user.shop)
    users: User[];

    @Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
    createdAt: Date;
}
