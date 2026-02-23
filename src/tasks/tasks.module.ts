import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { TasksService } from './tasks.service';
import { TasksController } from './tasks.controller';
import { Potion } from 'src/potion/potion.entity';
import { Shop } from 'src/shops/shops.entity';
import { User } from 'src/users/entities/user.entity';

@Module({
  imports: [TypeOrmModule.forFeature([Potion, Shop, User])],
  controllers: [TasksController],
  providers: [TasksService],
})
export class TasksModule {}
