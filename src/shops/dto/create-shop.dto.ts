import { IsNotEmpty, IsString, Length } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';


export class CreateShopDto {
    @ApiProperty({ 
        description: 'Name of the shop',
        example: 'Alchemist\'s Haven',
        minLength: 3,
        maxLength: 50,                              
    })
    @IsNotEmpty({ message: "Name is required" })
    @IsString()
    @Length(3, 50, { message: "Name must be between 3 and 50 characters" })
    name: string;
    @ApiProperty({ 
        description: 'Location of the shop',
        example: '123 Potion Street, Alchemy City',
        minLength: 5,
        maxLength: 100,
    })
    @IsNotEmpty({ message: "Location is required" })
    @IsString()
    @Length(5, 100, { message: "Location must be between 5 and 100 characters" })
    location: string;
}