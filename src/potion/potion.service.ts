import { Injectable } from '@nestjs/common';
import { Potion } from './potion.entity';
import { CreatePotionDto } from './dto/create-potion.dto';
import { Repository } from 'typeorm';
import { InjectRepository } from '@nestjs/typeorm';

@Injectable()
export class PotionService {
  constructor(
    @InjectRepository(Potion)
    private potionRepository: Repository<Potion>,
  ) {}

  async createPotionForShop(dto: CreatePotionDto, shopId: string): Promise<Potion> {
    const potion = this.potionRepository.create({
      ...dto,
      shopId, // ⚠️ Lie directement la potion à la boutique
    });
    return this.potionRepository.save(potion);
  }

  async findByShop(shopId: string): Promise<Potion[]> {
    return this.potionRepository.find({
      where: { shopId }, // ⚠️ Filtrage multi-tenant
      order: { createdAt: 'DESC' },
    });
  }

  async findAll(): Promise<Potion[]> {
    // Pour les admins uniquement
    return this.potionRepository.find({
      relations: ['shop'],
      order: { createdAt: 'DESC' },
    });
  }
}
