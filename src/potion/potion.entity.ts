import { Column, Entity, PrimaryGeneratedColumn, ManyToOne, JoinColumn } from 'typeorm';
import { Shop } from 'src/shops/shops.entity';

@Entity()
export class Potion {

    @PrimaryGeneratedColumn()
    private id: number;
    @Column()
    private name: string;
    @Column()
    private effect : string;
    @Column()
    private stock: number;
    @Column()
    private price: number;
    // eslint-disable-next-line @typescript-eslint/no-unsafe-return
    @ManyToOne(() => Shop, (shop) => shop.potions)
    @JoinColumn({ name: 'shopId' })
    shop: Shop;

    @Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
    private createdAt: Date;
}