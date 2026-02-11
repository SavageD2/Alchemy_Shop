import { Injectable } from '@nestjs/common';
import { Potion } from './potion.entity';
import { Repository } from 'typeorm';
import { InjectRepository } from '@nestjs/typeorm';

@Injectable()
export class PotionService {
    
    constructor(
        @InjectRepository(Potion) 
        private potionRepository: Repository<Potion>
    ) {}

    createPotion(potion: Potion): Promise<Potion> {
        return this.potionRepository.save(potion);
    }

    findAll(): Promise<Potion[]> {
        return this.potionRepository.find();
    }
}
