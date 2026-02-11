import { Injectable } from '@nestjs/common';
import { Shop } from './shops.entity';
import { Repository } from 'typeorm';
import { InjectRepository } from '@nestjs/typeorm';

@Injectable()
export class ShopsService {

    constructor(
        @InjectRepository(Shop) 
        private shopRepository: Repository<Shop>
    ){}

    createShop(shop: Shop): Promise<Shop> {
        return this.shopRepository.save(shop);
    }

    findAll(): Promise<Shop[]> {
        return this.shopRepository.find();
    }
}
