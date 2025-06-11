"""
Parallel execution utilities for autoprolab agents.

This module provides helper functions for common parallel execution patterns
used throughout the autoprolab system for efficient multi-target operations.
"""

import asyncio
from typing import List, Any, Dict, Optional, Callable
import logging

logger = logging.getLogger(__name__)

async def execute_parallel_with_timeout(
    tasks: List[Any], 
    timeout: int = 300,
    max_concurrent: Optional[int] = None
) -> List[Any]:
    """
    Execute tasks in parallel with timeout handling.
    
    Args:
        tasks: List of coroutine tasks to execute
        timeout: Maximum time in seconds to wait for all tasks
        max_concurrent: Maximum number of concurrent tasks (None for unlimited)
        
    Returns:
        List of results from task execution, with exceptions preserved
        
    Raises:
        asyncio.TimeoutError: If tasks don't complete within timeout
    """
    if not tasks:
        return []
    
    if max_concurrent and len(tasks) > max_concurrent:
        return await execute_parallel_batched(tasks, max_concurrent, timeout)
    
    try:
        results = await asyncio.wait_for(
            asyncio.gather(*tasks, return_exceptions=True),
            timeout=timeout
        )
        
        logger.info(f"Completed {len(tasks)} parallel tasks in {timeout}s timeout")
        return results
        
    except asyncio.TimeoutError:
        logger.error(f"Parallel execution timed out after {timeout}s")
        raise

async def execute_parallel_batched(
    tasks: List[Any], 
    batch_size: int, 
    timeout: int = 300
) -> List[Any]:
    """
    Execute tasks in parallel batches to limit concurrent operations.
    
    Args:
        tasks: List of coroutine tasks to execute
        batch_size: Number of tasks to run concurrently in each batch
        timeout: Maximum time in seconds for each batch
        
    Returns:
        List of results from all task executions
    """
    all_results = []
    
    for i in range(0, len(tasks), batch_size):
        batch = tasks[i:i + batch_size]
        logger.info(f"Executing batch {i//batch_size + 1} with {len(batch)} tasks")
        
        batch_results = await execute_parallel_with_timeout(batch, timeout)
        all_results.extend(batch_results)
    
    return all_results

async def execute_parallel_with_rate_limit(
    task_factory: Callable,
    targets: List[str],
    rate_limit: float = 1.0,
    timeout: int = 300
) -> List[Any]:
    """
    Execute tasks with rate limiting to prevent overwhelming target systems.
    
    Args:
        task_factory: Function that creates a task given a target
        targets: List of targets to process
        rate_limit: Minimum seconds between task starts
        timeout: Maximum time for all tasks
        
    Returns:
        List of results from task execution
    """
    tasks = []
    
    for i, target in enumerate(targets):
        if i > 0:
            await asyncio.sleep(rate_limit)
        
        task = task_factory(target)
        tasks.append(task)
        logger.debug(f"Started task for target {target}")
    
    return await execute_parallel_with_timeout(tasks, timeout)

async def execute_parallel_hosts(
    agent_method: Callable,
    hosts: List[str],
    method_kwargs: Optional[Dict] = None,
    timeout: int = 300,
    max_concurrent: int = 10
) -> Dict[str, Any]:
    """
    Execute an agent method against multiple hosts in parallel.
    
    Args:
        agent_method: The agent method to call for each host
        hosts: List of host IPs/hostnames to target
        method_kwargs: Additional keyword arguments for the agent method
        timeout: Maximum time for all operations
        max_concurrent: Maximum concurrent operations
        
    Returns:
        Dictionary mapping host to result
    """
    if method_kwargs is None:
        method_kwargs = {}
    
    tasks = []
    for host in hosts:
        task = agent_method(target=host, **method_kwargs)
        tasks.append(task)
    
    results = await execute_parallel_with_timeout(
        tasks, 
        timeout=timeout, 
        max_concurrent=max_concurrent
    )
    
    host_results = {}
    for i, host in enumerate(hosts):
        result = results[i]
        if isinstance(result, Exception):
            logger.error(f"Task failed for host {host}: {str(result)}")
            host_results[host] = {"error": str(result), "success": False}
        else:
            host_results[host] = result
    
    return host_results

def handle_parallel_exceptions(results: List[Any], targets: List[str]) -> Dict[str, Any]:
    """
    Process parallel execution results and handle exceptions gracefully.
    
    Args:
        results: Results from asyncio.gather with return_exceptions=True
        targets: List of targets corresponding to results
        
    Returns:
        Dictionary with success/failure status for each target
    """
    processed_results = {}
    
    for i, (target, result) in enumerate(zip(targets, results)):
        if isinstance(result, Exception):
            logger.warning(f"Operation failed for {target}: {str(result)}")
            processed_results[target] = {
                "success": False,
                "error": str(result),
                "exception_type": type(result).__name__
            }
        else:
            processed_results[target] = {
                "success": True,
                "result": result
            }
    
    successful_count = sum(1 for r in processed_results.values() if r["success"])
    logger.info(f"Parallel execution completed: {successful_count}/{len(targets)} successful")
    
    return processed_results

async def execute_with_fallback(
    primary_tasks: List[Any],
    fallback_factory: Optional[Callable] = None,
    timeout: int = 300
) -> List[Any]:
    """
    Execute tasks with fallback options for failed operations.
    
    Args:
        primary_tasks: Primary tasks to attempt
        fallback_factory: Function to create fallback tasks for failures
        timeout: Maximum time for execution
        
    Returns:
        List of results, with fallback results for failed primary tasks
    """
    primary_results = await execute_parallel_with_timeout(primary_tasks, timeout)
    
    if not fallback_factory:
        return primary_results
    
    fallback_tasks = []
    fallback_indices = []
    
    for i, result in enumerate(primary_results):
        if isinstance(result, Exception):
            fallback_task = fallback_factory(i)
            if fallback_task:
                fallback_tasks.append(fallback_task)
                fallback_indices.append(i)
    
    if fallback_tasks:
        logger.info(f"Executing {len(fallback_tasks)} fallback tasks")
        fallback_results = await execute_parallel_with_timeout(fallback_tasks, timeout)
        
        for idx, fallback_result in zip(fallback_indices, fallback_results):
            if not isinstance(fallback_result, Exception):
                primary_results[idx] = fallback_result
    
    return primary_results
