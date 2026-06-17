package hn.asta.hivora.board;

import hn.asta.hivora.auth.CurrentUser;
import hn.asta.hivora.common.ApiException;
import hn.asta.hivora.issue.Issue;
import hn.asta.hivora.issue.IssueRepository;
import hn.asta.hivora.project.Project;
import hn.asta.hivora.project.ProjectService;
import hn.asta.hivora.user.User;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;
import lombok.RequiredArgsConstructor;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Tag(name = "Boards")
@RestController
@RequestMapping("/api/v1/boards")
@RequiredArgsConstructor
public class BoardController {

	private final AgileBoardRepository boards;
	private final SprintRepository sprints;
	private final IssueRepository issues;
	private final ProjectService projects;
	private final CurrentUser currentUser;

	public record CreateBoardRequest(@NotBlank @Size(max = 120) String name,
			@NotEmpty List<String> projectIds, AgileBoard.Type type) {
	}

	public record SprintRequest(@NotBlank @Size(max = 120) String name, String goal,
			LocalDate startDate, LocalDate endDate) {
	}

	public record BoardColumnView(String name, List<String> states, Integer wipLimit,
			List<Issue> issues) {
	}

	public record BoardView(AgileBoard board, List<Sprint> sprints, List<BoardColumnView> columns) {
	}

	@GetMapping
	public List<AgileBoard> list(@RequestParam(required = false) String projectId) {
		User user = currentUser.require();
		List<AgileBoard> all = projectId != null
				? boards.findByProjectIdsContains(projectId)
				: boards.findAll();
		// Only surface boards the user may actually open. visibleTo already
		// excludes archived projects (a deactivated project's boards must never
		// surface) and applies direct-membership + team-grant access — mirroring
		// SprintService.assertAccess, so the overview matches what a card click
		// would allow. Admins see every active project's boards.
		Set<String> visible = visibleProjectIds(user);
		return all.stream()
				.filter(b -> b.getProjectIds().stream().anyMatch(visible::contains))
				.toList();
	}

	/** Ids of the projects the user may see (deduped, archived excluded). */
	private Set<String> visibleProjectIds(User user) {
		return projects.visibleTo(user).stream().map(Project::getId).collect(Collectors.toSet());
	}

	/** A board is accessible if it spans at least one project the user may see. */
	private void assertBoardAccess(AgileBoard board, User user) {
		if (user.isAdmin()) return;
		if (board.getProjectIds().stream().noneMatch(visibleProjectIds(user)::contains)) {
			throw ApiException.forbidden("error.accessDenied");
		}
	}

	@PostMapping
	@ResponseStatus(HttpStatus.CREATED)
	public AgileBoard create(@RequestBody @Valid CreateBoardRequest request) {
		String userId = currentUser.requireId();
		// Default columns mirror the first project's workflow.
		Project first = projects.get(request.projectIds().get(0));
		List<AgileBoard.Column> columns = new ArrayList<>();
		for (String state : first.workflowStateNames()) {
			columns.add(AgileBoard.Column.builder().name(state).states(List.of(state)).build());
		}
		return boards.save(AgileBoard.builder()
				.name(request.name())
				.type(request.type() != null ? request.type() : AgileBoard.Type.KANBAN)
				.projectIds(request.projectIds())
				.columns(columns)
				.ownerId(userId)
				.build());
	}

	@GetMapping("/{id}")
	public BoardView view(@PathVariable String id, @RequestParam(required = false) String sprintId) {
		User user = currentUser.require();
		AgileBoard board = boards.findById(id).orElseThrow(() -> ApiException.notFound("board"));
		assertBoardAccess(board, user);
		List<Sprint> boardSprints = sprints.findByBoardIdOrderByStartDateDesc(id);
		String effectiveSprint = sprintId != null ? sprintId : board.getActiveSprintId();

		List<Issue> candidates = new ArrayList<>();
		Set<String> active = projects.activeProjectIds();
		for (String projectId : board.getProjectIds()) {
			if (!active.contains(projectId)) continue; // skip archived projects
			if (effectiveSprint != null) {
				candidates.addAll(issues.findByProjectIdAndSprintId(projectId, effectiveSprint));
			}
			else {
				candidates.addAll(issues.findByProjectId(projectId,
						org.springframework.data.domain.PageRequest.of(0, 500)).getContent());
			}
		}
		candidates.sort(Comparator.comparingDouble(Issue::getRank));

		List<BoardColumnView> columnViews = new ArrayList<>();
		for (AgileBoard.Column column : board.getColumns()) {
			List<Issue> inColumn = candidates.stream()
					.filter(issue -> column.getStates().contains(issue.getState()))
					.toList();
			columnViews.add(new BoardColumnView(column.getName(), column.getStates(),
					column.getWipLimit(), inColumn));
		}
		return new BoardView(board, boardSprints, columnViews);
	}

	@PatchMapping("/{id}")
	public AgileBoard update(@PathVariable String id, @RequestBody AgileBoard updated) {
		User user = currentUser.require();
		AgileBoard board = boards.findById(id).orElseThrow(() -> ApiException.notFound("board"));
		assertBoardAccess(board, user);
		if (updated.getName() != null) board.setName(updated.getName());
		if (updated.getType() != null) board.setType(updated.getType());
		if (updated.getProjectIds() != null && !updated.getProjectIds().isEmpty()) {
			board.setProjectIds(updated.getProjectIds());
		}
		if (updated.getColumns() != null && !updated.getColumns().isEmpty()) {
			board.setColumns(updated.getColumns());
		}
		board.setActiveSprintId(updated.getActiveSprintId());
		return boards.save(board);
	}

	@DeleteMapping("/{id}")
	@ResponseStatus(HttpStatus.NO_CONTENT)
	public void delete(@PathVariable String id) {
		User user = currentUser.require();
		boards.findById(id).ifPresent(board -> {
			assertBoardAccess(board, user);
			boards.deleteById(id);
		});
	}

	@PostMapping("/{id}/sprints")
	@ResponseStatus(HttpStatus.CREATED)
	public Sprint createSprint(@PathVariable String id, @RequestBody @Valid SprintRequest request) {
		User user = currentUser.require();
		AgileBoard board = boards.findById(id).orElseThrow(() -> ApiException.notFound("board"));
		assertBoardAccess(board, user);
		return sprints.save(Sprint.builder()
				.boardId(id)
				.name(request.name())
				.goal(request.goal())
				.startDate(request.startDate())
				.endDate(request.endDate())
				.build());
	}
}
