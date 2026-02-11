import { Entity, Column, PrimaryGeneratedColumn, OneToMany } from 'typeorm';
import { Potion } from 'src/potion/potion.entity';

@Entity()
export class Shop {
    @PrimaryGeneratedColumn()
    private id: number;
    @Column()
    private name: string;
    @Column()
    private location: string;
    @OneToMany(() => Potion, (potion) => potion.shop)
    potions: Potion[];

    @Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
    private createdAt: Date;
}
