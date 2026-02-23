import { Controller, Post, UseGuards } from '@nestjs/common';
import { TasksService } from './tasks.service';
import { JwtAuthGuard } from 'src/auth/jwt-auth.guard';
import { RolesGuard } from 'src/auth/guards/auth.guards';
import { Roles } from 'src/auth/decorators/roles.decorator';
import { UserRole } from 'src/users/entities/user.entity';
import { ApiTags, ApiOperation, ApiBearerAuth } from '@nestjs/swagger';

@ApiTags('Tasks')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard, RolesGuard)
@Controller('tasks')
export class TasksController {
    constructor(private readonly tasksService: TasksService) {}

    @Post('check-stock')
    @Roles(UserRole.ADMIN)
    @ApiOperation({ summary: 'Check for low stock potions (Admin only)' })
    async triggerStockCheck() {
        await this.tasksService.checkLowStock();
        return { message: 'Low stock check triggered' };
    }

    @Post('daily-report')
    @Roles(UserRole.ADMIN)
    @ApiOperation({ summary: 'Generate daily report of potion sales (Admin only)' })
    async triggerDailyReport() {
        await this.tasksService.generateDailyReport();
        return { message: 'Daily report generation triggered' };
    }
}
