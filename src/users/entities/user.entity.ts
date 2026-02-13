import { Shop } from 'src/shops/shops.entity';
import { Column, CreateDateColumn, Entity, JoinColumn, ManyToOne, PrimaryGeneratedColumn } from 'typeorm';

export enum UserRole {
  ALCHIMIST = 'alchimist',
  ADMIN = 'admin',
}

@Entity()
export class User {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ unique: true })
  email: string;

  @Column({ select: false })
  password: string;

  @Column({
    type: 'enum',
    enum: UserRole,
    default: UserRole.ALCHIMIST,
  })
  role: UserRole;

  @ManyToOne(() => Shop, (shop) => shop.users, { nullable: true })
  @JoinColumn({ name: 'shopId' })
  shop: Shop;

  @Column({ nullable: true })
  shopId: string;

  @CreateDateColumn()
  createdAt: Date;
}
