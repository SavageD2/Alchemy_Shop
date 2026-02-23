import { IsNumber, IsPositive, IsString, Max, Min, Length } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { Type } from 'class-transformer';

export class CreatePotionDto {
  @ApiProperty({
    description: 'Name of the potion',
    example: 'Felix Felicis',
    minLength: 3,
    maxLength: 50,
  })
  @IsString({ message: 'Name must be a string' })
  @Length(3, 50, { message: 'Name must be between 3 and 50 characters' })
  name: string;

  @ApiProperty({
    description: 'Effect of the potion',
    example: 'Brings extraordinary luck to the drinker',
    minLength: 5,
    maxLength: 200,
  })
  @IsString({ message: 'Effect must be a string' })
  @Length(5, 200, { message: 'Effect must be between 5 and 200 characters' })
  effect: string;

  @ApiProperty({
    description: 'Stock quantity (can be 0)',
    example: 10,
    minimum: 0,
  })
  @Type(() => Number)
  @IsNumber({}, { message: 'Stock must be a number' })
  @Min(0, { message: 'Stock cannot be negative' })
  stock: number;

  @ApiProperty({
    description: 'Price of the potion',
    example: 150.0,
    minimum: 0.01,
    maximum: 10000,
  })
  @Type(() => Number)
  @IsNumber({}, { message: 'Price must be a number' })
  @IsPositive({ message: 'Price must be positive' })
  @Max(10000, { message: 'Price cannot exceed 10000' })
  price: number;
}