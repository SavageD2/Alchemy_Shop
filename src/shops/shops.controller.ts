import { Controller, Get, Post, UseGuards, Body, UsePipes } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiBearerAuth } from '@nestjs/swagger';
import { ShopsService } from './shops.service';
import { CreateShopDto } from './dto/create-shop.dto';
import { JwtAuthGuard } from 'src/auth/jwt-auth.guard';
import { RolesGuard } from 'src/auth/guards/auth.guards';
import { Roles } from 'src/auth/decorators/roles.decorator';
import { CurrentUser } from 'src/auth/decorators/current-user.decorator';
import { UserRole } from 'src/users/entities/user.entity';
import type { AuthenticatedUser } from 'src/auth/interfaces/auth-user.interface';
import { TrimPipe } from 'src/common/pipes/trim.pipe';

@ApiTags('Shops')
@ApiBearerAuth()
@Controller('shops')
@UseGuards(JwtAuthGuard, RolesGuard)
export class ShopsController {
  constructor(private readonly shopsService: ShopsService) {}

  @Post()
  @ApiOperation({ summary: 'Create a new shop (Admin only)' })
  @UsePipes(new TrimPipe())
  @Roles(UserRole.ADMIN)
  create(@Body() createShopDto: CreateShopDto) {
    return this.shopsService.createShop(createShopDto);
  }

  @Get()
  @ApiOperation({ summary: 'Get all shops (Admin only)' })
  @Roles(UserRole.ADMIN)
  findAll() {
    return this.shopsService.findAll();
  }

  @Get('my-shop')
  @ApiOperation({ summary: 'Get current user\'s shop' })
  getMyShop(@CurrentUser() user: AuthenticatedUser) {
    if (!user.shopId) {
      return { message: 'No shop assigned to this user' };
    }
    return this.shopsService.findOne(user.shopId);
  }
}
