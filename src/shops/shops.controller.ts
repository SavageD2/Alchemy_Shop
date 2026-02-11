import { Controller, Get, Post } from '@nestjs/common';
import { ShopsService } from './shops.service';
import { Shop } from './shops.entity';

@Controller('shops')
export class ShopsController {
  constructor(private readonly shopsService: ShopsService) {}

  @Post()
  create() {
    // Logique de création de boutique
    return this.shopsService.createShop(new Shop());
  }

  @Get()
  findAll() {
    return this.shopsService.findAll();
  }
}
