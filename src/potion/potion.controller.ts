import { Controller, Post, Get, UseGuards, Body, ForbiddenException } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiBearerAuth } from '@nestjs/swagger';
import { PotionService } from './potion.service';
import { CreatePotionDto } from './dto/create-potion.dto';
import { JwtAuthGuard } from 'src/auth/jwt-auth.guard';
import { CurrentUser } from 'src/auth/decorators/current-user.decorator';
import type { AuthenticatedUser } from 'src/auth/interfaces/auth-user.interface';

@ApiTags('Potions')
@ApiBearerAuth()
@Controller('potions')
@UseGuards(JwtAuthGuard)
export class PotionController {
  constructor(private readonly potionService: PotionService) {}

  @Post()
  @ApiOperation({ summary: 'Create a new potion for your shop' })
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
  @ApiOperation({ summary: 'Get all potions from your shop' })
  async getMyPotions(@CurrentUser() user: AuthenticatedUser) {
    if (!user.shopId) {
      return [];
    }
    return this.potionService.findByShop(user.shopId);
  }
}
