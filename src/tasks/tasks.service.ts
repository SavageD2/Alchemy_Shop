import { Injectable, Logger } from '@nestjs/common';
import { Cron, CronExpression, Interval, Timeout } from '@nestjs/schedule';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, LessThan } from 'typeorm';
import { Potion } from '../potion/potion.entity';

@Injectable()
export class TasksService {
  private readonly logger = new Logger(TasksService.name);

  constructor(
    @InjectRepository(Potion)
    private potionRepository: Repository<Potion>,
  ) {}

  @Cron(CronExpression.EVERY_HOUR)
  async checkLowStock() {
    this.logger.log('🔍 Checking for low stock potions...');

    try {
      const lowStockPotions = await this.potionRepository.find({
        where: { stock: LessThan(5) },
        relations: ['shop'],
      });

      if (lowStockPotions.length === 0) {
        this.logger.log('✅ All potions have sufficient stock');
        return;
      }

      this.logger.warn(
        `⚠️ Found ${lowStockPotions.length} potion(s) with low stock:`,
      );
      
      lowStockPotions.forEach((potion) => {
        this.logger.warn(
          `  - ${potion.name} (Stock: ${potion.stock}) at ${potion.shop?.name || 'Unknown Shop'}`,
        );
      });
    } catch (error) {
      this.logger.error('❌ Error checking low stock potions:', error);
    }
  }

  @Cron(CronExpression.EVERY_DAY_AT_MIDNIGHT)
  async generateDailyReport() {
    this.logger.log('📊 Generating daily report...');

    try {
      const totalPotions = await this.potionRepository.count();
      const result = await this.potionRepository
        .createQueryBuilder('potion')
        .select('SUM(potion.stock * potion.price)', 'totalValue')
        .getRawOne<{ totalValue: number }>();

      const totalValue = result?.totalValue || 0;

      this.logger.log(`📈 Daily Report - ${new Date().toISOString()}`);
      this.logger.log(`  📦 Total potions in stock: ${totalPotions}`);
      this.logger.log(`  💰 Total inventory value: $${totalValue}`);
    } catch (error) {
      this.logger.error('❌ Error generating daily report:', error);
    }
  }

  @Interval(30000)
  handleInterval() {
    this.logger.debug('⏱️ Heartbeat: Application is running');
  }

  @Timeout(10000)
  handleTimeout() {
    this.logger.log('🚀 Background tasks system initialized');
  }
}