import { Module } from '@nestjs/common';
import { ShopsService } from './shops.service';
import { ShopsController } from './shops.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Shop } from './shops.entity';

@Module({
  controllers: [ShopsController],
  imports: [TypeOrmModule.forFeature([Shop])],
  providers: [ShopsService],
})
export class ShopsModule {}
