import { Module } from '@nestjs/common';
import { PotionService } from './potion.service';
import { PotionController } from './potion.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Potion } from './potion.entity';

@Module({
  controllers: [PotionController],
  imports: [TypeOrmModule.forFeature([Potion])],
  providers: [PotionService],
})
export class PotionModule {}
