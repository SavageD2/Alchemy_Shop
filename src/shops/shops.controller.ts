import { Controller, Get, Post, UseGuards, Body } from '@nestjs/common';
import { ShopsService } from './shops.service';
import { JwtAuthGuard } from 'src/auth/jwt-auth.guard';
import { RolesGuard } from 'src/auth/guards/auth.guards';
import { Roles } from 'src/auth/decorators/roles.decorator';
import { CurrentUser } from 'src/auth/decorators/current-user.decorator';
import { UserRole } from 'src/users/entities/user.entity';
import type { AuthenticatedUser } from 'src/auth/interfaces/auth-user.interface';

@Controller('shops')
@UseGuards(JwtAuthGuard, RolesGuard) // Guards globaux pour tout le controller
export class ShopsController {
  constructor(private readonly shopsService: ShopsService) {}

  @Post()
  @Roles(UserRole.ADMIN) // Seuls les admins peuvent créer des boutiques
  create(@Body() createShopDto: { name: string; location: string }) {
    return this.shopsService.createShop(createShopDto);
  }

  @Get()
  @Roles(UserRole.ADMIN) // Seuls les admins voient toutes les boutiques
  findAll() {
    return this.shopsService.findAll();
  }

  @Get('my-shop')
  getMyShop(@CurrentUser() user: AuthenticatedUser) {
    if (!user.shopId) {
      return { message: 'No shop assigned to this user' };
    }
    return this.shopsService.findOne(user.shopId);
  }
}
