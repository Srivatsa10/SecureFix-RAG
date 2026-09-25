import { render, screen } from '@testing-library/react';

import { shippedResult } from '../test/fixtures';
import { ScoreBars } from './ScoreBars';

describe('ScoreBars', () => {
  it('renders one meter per dimension and flags those below threshold', () => {
    const scores = shippedResult.scores;
    if (!scores) throw new Error('fixture must have scores');
    render(<ScoreBars scores={scores} threshold={0.85} />);

    const meters = screen.getAllByRole('meter');
    expect(meters).toHaveLength(3);
    expect(screen.getByRole('meter', { name: 'Framework fit' })).toHaveAttribute('aria-valuenow', '0.8');
    expect(screen.getByText('0.80 ✗')).toBeInTheDocument();
    expect(screen.getByText('0.99 ✓')).toBeInTheDocument();
  });
});
