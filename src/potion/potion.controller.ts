import { Controller, Post, Get } from '@nestjs/common';
import { PotionService } from './potion.service';
import { Potion } from './potion.entity';

@Controller('potion')
export class PotionController {
  constructor(private readonly potionService: PotionService) {}

  @Post()
  create() {
    // Logique de création de potion
    return this.potionService.createPotion(new Potion());
  }

  @Get()
  findAll() {
    return this.potionService.findAll();
  }
}
