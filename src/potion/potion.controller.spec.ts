import { Test, TestingModule } from '@nestjs/testing';
import { PotionController } from './potion.controller';
import { PotionService } from './potion.service';

describe('PotionController', () => {
  let controller: PotionController;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [PotionController],
      providers: [PotionService],
    }).compile();

    controller = module.get<PotionController>(PotionController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });
});
