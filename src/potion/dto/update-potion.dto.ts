import { CreatePotionDto } from './create-potion.dto';
import { PartialType } from '@nestjs/swagger';


export class UpdatePotionDto extends PartialType(CreatePotionDto) {
	
}