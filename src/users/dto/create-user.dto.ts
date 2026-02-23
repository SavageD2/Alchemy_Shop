import { IsEmail, IsEnum, IsOptional, IsString, IsUUID, MinLength } from 'class-validator';
import { Transform } from 'class-transformer';
import { ApiProperty } from '@nestjs/swagger';
import { UserRole } from '../entities/user.entity';

export class CreateUserDto {
  @ApiProperty({
    description: 'Email address of the user',
    example: 'merlin@alchimia.com',
  })
  @Transform(({ value }) => (typeof value === 'string' ? value.toLowerCase().trim() : value))
  @IsEmail({}, { message: 'Email must be valid' })
  email: string;

  @ApiProperty({
    description: 'User password',
    example: 'potion123',
    minLength: 6,
  })
  @IsString()
  @MinLength(6, { message: 'Password must be at least 6 characters' })
  password: string;

  @ApiProperty({
    description: 'User role (admin or alchimist)',
    enum: UserRole,
    required: false,
    default: UserRole.ALCHIMIST,
  })
  @IsOptional()
  @IsEnum(UserRole, { message: 'Role must be either admin or alchimist' })
  role?: UserRole;

  @ApiProperty({
    description: 'Shop ID the user belongs to',
    example: '123e4567-e89b-12d3-a456-426614174000',
    required: false,
  })
  @IsOptional()
  @IsUUID(4, { message: 'Shop ID must be a valid UUID' })
  shopId?: string;
}
