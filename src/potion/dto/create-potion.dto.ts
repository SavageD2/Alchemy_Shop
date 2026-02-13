import { IsNumber, IsString } from "class-validator";



export class CreatePotionDto {
    @IsString()
    name: string;
    @IsString()
    effect : string;
    @IsNumber()
    stock: number;
    @IsNumber()
    price: number;
}