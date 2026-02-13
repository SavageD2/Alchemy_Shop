import { Injectable } from '@nestjs/common';
import { Shop } from './shops.entity';
import { Repository } from 'typeorm';
import { InjectRepository } from '@nestjs/typeorm';

@Injectable()
export class ShopsService {
  constructor(
    @InjectRepository(Shop)
    private shopRepository: Repository<Shop>,
  ) {}

  createShop(shopData: { name: string; location: string }): Promise<Shop> {
    const shop = this.shopRepository.create(shopData);
    return this.shopRepository.save(shop);
  }

  findAll(): Promise<Shop[]> {
    return this.shopRepository.find({
      relations: ['users', 'potions'],
    });
  }

  findOne(id: string): Promise<Shop | null> {
    return this.shopRepository.findOne({
      where: { id },
      relations: ['users', 'potions'],
    });
  }
}
