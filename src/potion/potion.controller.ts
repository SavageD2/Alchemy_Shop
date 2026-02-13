import { Controller, Post, Get, UseGuards, Body, ForbiddenException } from '@nestjs/common';
import { PotionService } from './potion.service';
import { CreatePotionDto } from './dto/create-potion.dto';
import { JwtAuthGuard } from 'src/auth/jwt-auth.guard';
import { CurrentUser } from 'src/auth/decorators/current-user.decorator';
import type { AuthenticatedUser } from 'src/auth/interfaces/auth-user.interface';

@Controller('potions')
@UseGuards(JwtAuthGuard) // Toutes les routes nécessitent une authentification
export class PotionController {
  constructor(private readonly potionService: PotionService) {}

  @Post()
  async createPotion(
    @Body() createPotionDto: CreatePotionDto,
    @CurrentUser() user: AuthenticatedUser,
  ) {
    if (!user.shopId) {
      throw new ForbiddenException('You must be assigned to a shop to create potions');
    }
    return this.potionService.createPotionForShop(createPotionDto, user.shopId);
  }

  @Get()
  async getMyPotions(@CurrentUser() user: AuthenticatedUser) {
    if (!user.shopId) {
      return [];
    }
    return this.potionService.findByShop(user.shopId);
  }
}
